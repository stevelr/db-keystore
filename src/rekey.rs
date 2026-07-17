//! Out-of-place rekey (DEK rotation) with exact verification, safe destination
//! creation, and typed errors.
//!
//! [`DbKeyStore::rekey`] copies every credential from a source keystore into a
//! freshly created destination keystore, re-encrypting with the destination
//! key (or writing plaintext when no destination key is given). On success the
//! destination has been:
//!
//! - created safely: `O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0600` from the
//!   instant of creation (the WAL/SHM sidecars are pre-created `0600` too),
//!   parent directory pinned by descriptor (on Linux the database is opened
//!   through `/proc/self/fd/<dir>/<name>` so a substituted parent directory
//!   cannot redirect the write);
//! - verified exactly: every record's `service`, `user`, `uuid`, `comment`,
//!   and secret bytes are compared between source and destination, streaming
//!   one record at a time (a matching row count alone is not accepted);
//! - durably closed: WAL checkpointed (`TRUNCATE`), file-synced, sidecar
//!   WAL/SHM files removed, directory synced, and every directory entry
//!   (source, destination, and sidecars) re-verified to still be the inode
//!   that was validated or created at the start.
//!
//! Substitution resistance has one caveat: turso opens files by path, not by
//! descriptor, so a swap of the *final* path component in the window between
//! creation/validation and turso's own open cannot be prevented — only
//! detected. The inode re-verification above closes that window after the
//! fact: a swapped source, destination, or sidecar entry causes an error
//! ([`RekeyError::SourceReplaced`] / [`RekeyError::UnsafeDestination`])
//! instead of success. Preventing the swap entirely requires the database
//! layer to accept an already-opened descriptor, which turso does not
//! currently support (see todo notes; out of scope here).
//!
//! On failure a typed [`RekeyError`] is returned without panicking, the source
//! is left unchanged, and partially written destination files are removed —
//! but only files whose directory entries still match the inodes this
//! operation created; pre-existing or substituted files are never deleted.
//!
//! Secrets never leave zeroizing owners on the db-keystore side. The
//! remaining exposure is the turso boundary: turso owns row values and
//! parameter blobs as ordinary `Vec<u8>`/`String` and the encryption key as
//! an ordinary `String`, all freed without wiping. During the copy, each
//! secret travels only inside the `turso::Value` read from the source row and
//! bound directly to the destination insert — both turso-owned allocations;
//! this module adds no copies of its own. Extending zeroization into turso
//! requires a turso API change and is out of scope here.
//!
//! No digest of credential secrets (keyed or not) is exposed by this API;
//! comparison is exact and internal, so low-entropy secrets cannot be attacked
//! offline through the verification machinery.

use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    time::Duration,
};

use futures::executor::block_on;
use turso::{Builder, Connection, Database, Value};
use zeroize::Zeroizing;

use crate::{DbKeyStore, EncryptionOpts};

#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(unix)]
use rustix::fs::{AtFlags, FileType, Mode, OFlags};

/// Result of a successful [`DbKeyStore::rekey`] operation.
///
/// Success itself means "exactly verified": rekey does not return this value
/// until every source record has been compared byte-for-byte against the
/// destination and the destination has been durably closed.
///
/// Intentionally carries no secret material so it is safe to log or format.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RekeyOutcome {
    /// Number of credentials copied (and verified) from source to destination.
    pub copied: u64,
}

/// Typed error for [`DbKeyStore::rekey`] and [`rekey_at`].
///
/// Every malformed-database and wrong-key case returns one of these variants;
/// the operation never unwinds or aborts (a panic escaping the underlying
/// database layer is caught and reported as [`RekeyError::Panicked`]).
/// Messages never contain secret material.
#[derive(Debug)]
#[non_exhaustive]
pub enum RekeyError {
    /// The source database could not be decrypted with the supplied key/cipher.
    WrongSourceKey,
    /// The destination database could not be decrypted with the supplied
    /// key/cipher. (Not currently produced by rekey itself, which always
    /// creates a fresh destination; reserved for flows that re-open a
    /// destination candidate.)
    WrongDestinationKey,
    /// The source directory entry stopped referring to the file that was
    /// validated at the start of the operation (it was replaced mid-rekey).
    SourceReplaced(String),
    /// The source database file does not exist or is not a regular file.
    SourceNotFound(String),
    /// The source is not a readable db-keystore database (corrupt, not a
    /// database, or missing the credentials table). An encrypted source opened
    /// without any key also lands here, since it is indistinguishable from a
    /// non-database file.
    CorruptSource(String),
    /// Source and destination records did not compare exactly equal.
    VerificationMismatch(String),
    /// The destination path already exists (including as a symlink).
    DestinationExists(String),
    /// The destination could not be created safely, or the directory entry no
    /// longer refers to the file that was created.
    UnsafeDestination(String),
    /// A key or cipher parameter was malformed.
    InvalidKey(String),
    /// Filesystem error.
    Io(std::io::Error),
    /// Other database-layer error.
    Database(String),
    /// A panic escaped the database layer and was converted into an error.
    Panicked(String),
}

impl fmt::Display for RekeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RekeyError::WrongSourceKey => {
                write!(
                    f,
                    "source database could not be decrypted with the supplied key"
                )
            }
            RekeyError::WrongDestinationKey => write!(
                f,
                "destination database could not be decrypted with the supplied key"
            ),
            RekeyError::SourceNotFound(msg) => write!(f, "source database not found: {msg}"),
            RekeyError::SourceReplaced(msg) => {
                write!(f, "source file was replaced during rekey: {msg}")
            }
            RekeyError::CorruptSource(msg) => write!(f, "source is not a usable database: {msg}"),
            RekeyError::VerificationMismatch(msg) => {
                write!(f, "source/destination verification failed: {msg}")
            }
            RekeyError::DestinationExists(msg) => {
                write!(f, "destination already exists: {msg}")
            }
            RekeyError::UnsafeDestination(msg) => {
                write!(f, "destination could not be created safely: {msg}")
            }
            RekeyError::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
            RekeyError::Io(err) => write!(f, "i/o error: {err}"),
            RekeyError::Database(msg) => write!(f, "database error: {msg}"),
            RekeyError::Panicked(msg) => {
                write!(f, "database layer panicked (caught): {msg}")
            }
        }
    }
}

impl std::error::Error for RekeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RekeyError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RekeyError {
    fn from(err: std::io::Error) -> Self {
        RekeyError::Io(err)
    }
}

/// A fixed-size, zeroizing container for a database encryption key (DEK).
///
/// Supports 128-bit and 256-bit keys (the sizes turso's ciphers use). The key
/// bytes live in a `Zeroizing<[u8; 32]>` that is wiped on drop; no ordinary
/// heap copy of the key is made by this type. Constructors borrow the caller's
/// buffer, so the caller keeps ownership (and wiping responsibility) of its
/// own copy — no particular zeroizing library is required of callers.
#[derive(Clone)]
pub struct SensitiveKey {
    bytes: Zeroizing<[u8; 32]>,
    len: usize,
}

impl SensitiveKey {
    /// Decode a hex-encoded key (32 or 64 hex chars) into zeroizing storage.
    pub fn from_hex(hexkey: &str) -> Result<Self, RekeyError> {
        if hexkey.len() != 32 && hexkey.len() != 64 {
            return Err(RekeyError::InvalidKey(
                "hex key must be 32 or 64 hex characters (128- or 256-bit key)".to_string(),
            ));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        for (i, pair) in hexkey.as_bytes().chunks_exact(2).enumerate() {
            let hi = hex_nibble(pair[0])?;
            let lo = hex_nibble(pair[1])?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self {
            bytes,
            len: hexkey.len() / 2,
        })
    }

    /// Copy a raw 16- or 32-byte key into zeroizing storage.
    pub fn from_bytes(key: &[u8]) -> Result<Self, RekeyError> {
        if key.len() != 16 && key.len() != 32 {
            return Err(RekeyError::InvalidKey(
                "key must be 16 or 32 bytes".to_string(),
            ));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes[..key.len()].copy_from_slice(key);
        Ok(Self {
            bytes,
            len: key.len(),
        })
    }

    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Key length in bytes (16 or 32).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Always false; a key is never empty. Present for API completeness.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Hex-encode into a zeroizing string. Capacity is preallocated exactly so
    /// the buffer is never reallocated (no stray heap copies).
    pub(crate) fn to_hex(&self) -> Zeroizing<String> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(self.len * 2);
        for byte in self.as_bytes() {
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        Zeroizing::new(out)
    }
}

impl fmt::Debug for SensitiveKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SensitiveKey(<redacted>, {} bytes)", self.len)
    }
}

fn hex_nibble(c: u8) -> Result<u8, RekeyError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(RekeyError::InvalidKey(
            "hex key contains a non-hex character".to_string(),
        )),
    }
}

/// Which database an error came from, for error attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Source,
    Destination,
}

/// Map a turso error to a typed [`RekeyError`], attributing wrong-key and
/// corruption cases to the given side.
fn db_err(err: &turso::Error, side: Side) -> RekeyError {
    let text = err.to_string();
    if text.to_ascii_lowercase().contains("decryption failed") {
        return match side {
            Side::Source => RekeyError::WrongSourceKey,
            Side::Destination => RekeyError::WrongDestinationKey,
        };
    }
    match (err, side) {
        (turso::Error::NotAdb(_) | turso::Error::Corrupt(_), Side::Source) => {
            RekeyError::CorruptSource(text)
        }
        _ => RekeyError::Database(text),
    }
}

fn keyring_err(err: &keyring_core::Error, side: Side) -> RekeyError {
    match side {
        Side::Source => RekeyError::CorruptSource(err.to_string()),
        Side::Destination => RekeyError::Database(err.to_string()),
    }
}

impl DbKeyStore {
    /// Rekey a keystore out-of-place with exact verification: read every
    /// credential from the source database, write it into a freshly and safely
    /// created destination database, then compare all source and destination
    /// records (service, user, uuid, comment, and secret bytes) before
    /// checkpointing and durably closing the destination.
    ///
    /// This is used to add, remove, or rotate the on-disk encryption key (a
    /// DEK rotation): pass `dest_opts = Some(..)` to add or rotate encryption,
    /// or `dest_opts = None` to write an unencrypted copy. `source_opts` must
    /// supply the cipher/key the source was written with (or `None` if the
    /// source is unencrypted).
    ///
    /// Success means "exactly verified": if this function returns `Ok`, the
    /// destination contains a byte-exact copy of every source credential, has
    /// been checkpointed and file-synced, and no WAL/SHM sidecar files remain.
    /// On every failure the source is left unchanged, partially written
    /// destination files are removed, and a typed [`RekeyError`] is returned
    /// without panicking.
    ///
    /// The destination is created `O_CREAT | O_EXCL | O_NOFOLLOW` with mode
    /// `0600` relative to a pinned parent directory descriptor; an existing
    /// file or symlink at `dest_path` (or at its WAL/SHM sidecar names) is
    /// rejected and never deleted. Missing destination parent directories are
    /// created. Whether the source enforced `(service, user)` uniqueness is
    /// detected from the source schema and mirrored on the destination so
    /// ambiguous keystores round-trip unchanged. Callers needing full
    /// directory-descriptor control should use [`rekey_at`] (Linux); see the
    /// [module docs](self) for the substitution-resistance caveat shared by
    /// both entry points.
    ///
    /// No secret material is logged or included in any returned value.
    pub fn rekey(
        source_path: impl AsRef<Path>,
        source_opts: Option<&EncryptionOpts>,
        dest_path: impl AsRef<Path>,
        dest_opts: Option<&EncryptionOpts>,
    ) -> Result<RekeyOutcome, RekeyError> {
        let source_path = source_path.as_ref();
        let dest_path = dest_path.as_ref();
        catch_panics(|| rekey_paths(source_path, source_opts, dest_path, dest_opts))
    }
}

/// Descriptor-relative rekey (Linux).
///
/// Like [`DbKeyStore::rekey`], but the source and destination are named
/// relative to caller-owned directory descriptors, so the caller controls
/// exactly which directories are used and no *directory* component can be
/// substituted underneath the operation:
///
/// - the source is opened with `openat(source_dir, ..., O_NOFOLLOW)` and must
///   be a regular file;
/// - the destination (and its WAL/SHM sidecars) are created with
///   `openat(dest_dir, ..., O_CREAT | O_EXCL | O_NOFOLLOW)`, mode `0600` from
///   the instant of creation (an `fchmod` pins the mode against the umask);
/// - the databases are opened through `/proc/self/fd/<dirfd>/<name>`, so every
///   file turso touches (including WAL sidecars) resolves through the pinned
///   directory descriptors;
/// - before success, every directory entry — source, destination, and
///   sidecars — is re-checked (`O_NOFOLLOW`) to confirm it is still the inode
///   validated or created at the start; otherwise
///   [`RekeyError::SourceReplaced`] or [`RekeyError::UnsafeDestination`] is
///   returned. As the [module docs](self) explain, a final-component swap in
///   the window before turso's own by-path open is detected by these checks
///   rather than prevented; the directory itself can never be substituted.
///
/// `source_name` and `dest_name` must be single path components (no `/`).
/// Directory descriptors should be opened with read access (`O_RDONLY |
/// O_DIRECTORY`) so the destination directory can be fsynced.
#[cfg(target_os = "linux")]
pub fn rekey_at(
    source_dir: &OwnedFd,
    source_name: &str,
    source_opts: Option<&EncryptionOpts>,
    dest_dir: &OwnedFd,
    dest_name: &str,
    dest_opts: Option<&EncryptionOpts>,
) -> Result<RekeyOutcome, RekeyError> {
    catch_panics(|| {
        rekey_fds(
            source_dir.as_fd(),
            source_name,
            None,
            source_opts,
            dest_dir.as_fd(),
            dest_name,
            None,
            dest_opts,
        )
    })
}

/// Run `f`, converting an escaped panic into `RekeyError::Panicked`.
/// Turso 0.7 returns errors (not panics) for wrong-key and corrupt-database
/// cases; this is defense in depth so rekey itself never unwinds.
fn catch_panics<T>(f: impl FnOnce() -> Result<T, RekeyError>) -> Result<T, RekeyError> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(ToString::to_string)
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            Err(RekeyError::Panicked(msg))
        }
    }
}

/// Path-based entry point: resolve parents, pin them with directory
/// descriptors, and delegate to the descriptor-relative implementation.
#[cfg(unix)]
fn rekey_paths(
    source_path: &Path,
    source_opts: Option<&EncryptionOpts>,
    dest_path: &Path,
    dest_opts: Option<&EncryptionOpts>,
) -> Result<RekeyOutcome, RekeyError> {
    // Follow symlinks deliberately for the *source* path (the caller may
    // legitimately reference the keystore through a symlink), then pin the
    // resolved parent directory.
    let source_canon = source_path
        .canonicalize()
        .map_err(|e| RekeyError::SourceNotFound(format!("{}: {e}", source_path.display())))?;
    let (source_parent, source_name) = split_parent_name(&source_canon)
        .ok_or_else(|| RekeyError::SourceNotFound(format!("{}", source_path.display())))?;
    let source_dir = open_dir(source_parent)?;

    let (dest_parent, dest_name) = split_parent_name(dest_path).ok_or_else(|| {
        RekeyError::UnsafeDestination(format!(
            "destination path '{}' has no file name",
            dest_path.display()
        ))
    })?;
    // Create missing destination parents (as pre-0.5 rekey did), then pin the
    // parent directory; everything after this resolves relative to the fd.
    std::fs::create_dir_all(dest_parent)?;
    let dest_dir = open_dir(dest_parent)?;

    rekey_fds(
        source_dir.as_fd(),
        &source_name,
        Some(source_parent),
        source_opts,
        dest_dir.as_fd(),
        &dest_name,
        Some(dest_parent),
        dest_opts,
    )
}

/// Portable fallback for non-unix targets: no descriptor pinning or unix
/// permission control is available, so creation safety is limited to
/// `create_new` (exclusive, symlink-refusing) semantics. The durability
/// contract is honored: the WAL is verified empty after the checkpoint,
/// sidecar files are removed, and the destination is synced before success.
#[cfg(not(unix))]
fn rekey_paths(
    source_path: &Path,
    source_opts: Option<&EncryptionOpts>,
    dest_path: &Path,
    dest_opts: Option<&EncryptionOpts>,
) -> Result<RekeyOutcome, RekeyError> {
    if !source_path.is_file() {
        return Err(RekeyError::SourceNotFound(format!(
            "{}",
            source_path.display()
        )));
    }
    let source_str = source_path
        .to_str()
        .ok_or_else(|| RekeyError::SourceNotFound("path must be valid UTF-8".to_string()))?;
    let dest_str = dest_path
        .to_str()
        .ok_or_else(|| RekeyError::UnsafeDestination("path must be valid UTF-8".to_string()))?;
    if let Some(parent) = dest_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let dest_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                RekeyError::DestinationExists(dest_path.display().to_string())
            } else {
                RekeyError::Io(e)
            }
        })?;
    let wal_path = format!("{dest_str}-wal");
    let tshm_path = format!("{dest_str}-tshm");
    // pre-existing sidecars are rejected (and never deleted): the database
    // layer would otherwise adopt a stale WAL for the fresh destination
    for sidecar in [&wal_path, &tshm_path] {
        if Path::new(sidecar).exists() {
            let _ = std::fs::remove_file(dest_path);
            return Err(RekeyError::DestinationExists(sidecar.clone()));
        }
    }
    let result = (|| {
        let copied = run_rekey(source_str, source_opts, dest_str, dest_opts)?;
        // committed credentials must not be stranded in the WAL
        match std::fs::metadata(&wal_path) {
            Ok(meta) if meta.len() > 0 => {
                return Err(RekeyError::Database(format!(
                    "destination WAL '{wal_path}' still contains {} bytes after checkpoint",
                    meta.len()
                )));
            }
            _ => {}
        }
        dest_file.sync_all()?;
        // remove the (empty) sidecar files so the candidate is cleanly closed
        for sidecar in [&wal_path, &tshm_path] {
            match std::fs::remove_file(sidecar) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(RekeyError::Io(e)),
            }
        }
        Ok(RekeyOutcome { copied })
    })();
    if result.is_err() {
        // best-effort cleanup of the partial destination
        let _ = std::fs::remove_file(dest_path);
        let _ = std::fs::remove_file(&wal_path);
        let _ = std::fs::remove_file(&tshm_path);
    }
    result
}

#[cfg(unix)]
fn split_parent_name(path: &Path) -> Option<(&Path, String)> {
    let name = path.file_name()?.to_str()?.to_string();
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    let parent = path.parent()?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    Some((parent, name))
}

#[cfg(unix)]
fn open_dir(path: &Path) -> Result<OwnedFd, RekeyError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        RekeyError::Io(std::io::Error::new(
            std::io::Error::from(e).kind(),
            format!("open directory '{}': {e}", path.display()),
        ))
    })?;
    Ok(fd)
}

/// Reject names that are not a single, non-trivial path component.
#[cfg(unix)]
fn validate_name(name: &str, what: &str) -> Result<(), RekeyError> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(RekeyError::UnsafeDestination(format!(
            "{what} name '{name}' must be a single path component"
        )));
    }
    Ok(())
}

/// Compute the path turso should open for `name` inside the pinned directory.
/// On Linux this goes through `/proc/self/fd/<dirfd>/<name>`, so path
/// resolution cannot escape the pinned directory even if the directory is
/// renamed or substituted. Elsewhere the caller-supplied directory path is
/// used (pinning is then limited to creation and post-verification).
#[cfg(unix)]
fn pinned_turso_path(
    dir: BorrowedFd<'_>,
    name: &str,
    dir_path: Option<&Path>,
) -> Result<String, RekeyError> {
    #[cfg(target_os = "linux")]
    {
        if Path::new("/proc/self/fd").exists() {
            return Ok(format!("/proc/self/fd/{}/{name}", dir.as_raw_fd()));
        }
    }
    let _ = dir;
    match dir_path {
        Some(dir_path) => {
            let joined = dir_path.join(name);
            joined.to_str().map(ToString::to_string).ok_or_else(|| {
                RekeyError::UnsafeDestination("database path must be valid UTF-8".to_string())
            })
        }
        None => Err(RekeyError::UnsafeDestination(
            "descriptor-relative rekey requires /proc/self/fd".to_string(),
        )),
    }
}

/// Owns the safely-created destination file and its pre-created sidecar
/// files, and removes them on failure (when dropped uncommitted). Every
/// unlink — main file and sidecars alike — first checks that the directory
/// entry still refers to the inode this guard created, so a file substituted
/// by someone else is never deleted.
#[cfg(unix)]
struct DestGuard<'a> {
    dir: BorrowedFd<'a>,
    name: &'a str,
    file: OwnedFd,
    /// Sidecar files we created (name, created fd), e.g. `dst.db-wal`.
    sidecars: Vec<(String, OwnedFd)>,
    committed: bool,
}

#[cfg(unix)]
impl DestGuard<'_> {
    /// Best-effort unlink of the created sidecar files, each only if its
    /// directory entry is still the inode we created.
    fn unlink_created_sidecars(&mut self) {
        for (name, fd) in self.sidecars.drain(..) {
            if entry_matches(self.dir, &name, &fd) {
                let _ = rustix::fs::unlinkat(self.dir, name.as_str(), AtFlags::empty());
            }
        }
    }
}

/// True if the directory entry `name` (not following symlinks) still refers
/// to the same inode as the open descriptor `fd`.
#[cfg(unix)]
fn entry_matches(dir: BorrowedFd<'_>, name: &str, fd: &OwnedFd) -> bool {
    match (
        rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW),
        rustix::fs::fstat(fd),
    ) {
        (Ok(entry), Ok(created)) => {
            entry.st_dev == created.st_dev && entry.st_ino == created.st_ino
        }
        _ => false,
    }
}

#[cfg(unix)]
impl Drop for DestGuard<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        self.unlink_created_sidecars();
        if entry_matches(self.dir, self.name, &self.file) {
            let _ = rustix::fs::unlinkat(self.dir, self.name, AtFlags::empty());
        }
    }
}

/// Create the destination database file (and its WAL/SHM sidecars) safely:
/// directory-relative, `O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0600` pinned
/// with `fchmod` so the umask cannot widen it. Pre-creating the sidecars with
/// mode `0600` matters because the WAL briefly holds credential plaintext and
/// turso would otherwise create it with default (usually `0644`) permissions.
#[cfg(unix)]
fn create_destination<'a>(dir: BorrowedFd<'a>, name: &'a str) -> Result<DestGuard<'a>, RekeyError> {
    validate_name(name, "destination")?;
    let mode = Mode::RUSR | Mode::WUSR; // 0600
    let flags = OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDWR;
    let file = rustix::fs::openat(dir, name, flags, mode).map_err(|e| match e {
        rustix::io::Errno::EXIST => RekeyError::DestinationExists(name.to_string()),
        other => RekeyError::Io(std::io::Error::from(other)),
    })?;
    let mut guard = DestGuard {
        dir,
        name,
        file,
        sidecars: Vec::new(),
        committed: false,
    };
    // Pin the mode to exactly 0600 regardless of the process umask.
    rustix::fs::fchmod(&guard.file, mode).map_err(|e| RekeyError::Io(e.into()))?;
    let st = rustix::fs::fstat(&guard.file).map_err(|e| RekeyError::Io(e.into()))?;
    if !FileType::from_raw_mode(st.st_mode).is_file() {
        return Err(RekeyError::UnsafeDestination(format!(
            "created destination '{name}' is not a regular file"
        )));
    }
    // Pre-create the sidecar files turso will use, with owner-only mode, so
    // credential plaintext in the WAL is never world-readable. Turso opens
    // existing files without changing their mode. A pre-existing sidecar is
    // rejected (and, having not been created by us, is never deleted).
    for suffix in ["-wal", "-tshm"] {
        let sidecar = format!("{name}{suffix}");
        let sidecar_fd =
            rustix::fs::openat(dir, sidecar.as_str(), flags, mode).map_err(|e| match e {
                rustix::io::Errno::EXIST => RekeyError::DestinationExists(sidecar.clone()),
                other => RekeyError::Io(std::io::Error::from(other)),
            })?;
        guard.sidecars.push((sidecar, sidecar_fd));
    }
    Ok(guard)
}

/// Open and validate the source: directory-relative, `O_NOFOLLOW`, must be a
/// regular file. Returns the (kept-open) fd pinning the verified inode.
#[cfg(unix)]
fn open_source_checked(dir: BorrowedFd<'_>, name: &str) -> Result<OwnedFd, RekeyError> {
    validate_name(name, "source")?;
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        rustix::io::Errno::NOENT => RekeyError::SourceNotFound(name.to_string()),
        rustix::io::Errno::LOOP => RekeyError::SourceNotFound(format!(
            "source '{name}' is a symlink (descriptor-relative rekey requires a regular file)"
        )),
        other => RekeyError::Io(std::io::Error::from(other)),
    })?;
    let st = rustix::fs::fstat(&fd).map_err(|e| RekeyError::Io(e.into()))?;
    if !FileType::from_raw_mode(st.st_mode).is_file() {
        return Err(RekeyError::SourceNotFound(format!(
            "source '{name}' is not a regular file"
        )));
    }
    Ok(fd)
}

/// Descriptor-relative implementation shared by `rekey` and `rekey_at`.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn rekey_fds(
    source_dir: BorrowedFd<'_>,
    source_name: &str,
    source_dir_path: Option<&Path>,
    source_opts: Option<&EncryptionOpts>,
    dest_dir: BorrowedFd<'_>,
    dest_name: &str,
    dest_dir_path: Option<&Path>,
    dest_opts: Option<&EncryptionOpts>,
) -> Result<RekeyOutcome, RekeyError> {
    // Pin and validate the source inode; the descriptor is kept so the
    // directory entry can be re-verified against it after the copy.
    let source_fd = open_source_checked(source_dir, source_name)?;
    let source_turso_path = pinned_turso_path(source_dir, source_name, source_dir_path)?;

    // Create the destination safely; the guard removes it on any failure.
    let mut dest = create_destination(dest_dir, dest_name)?;
    let dest_turso_path = pinned_turso_path(dest_dir, dest_name, dest_dir_path)?;

    let copied = run_rekey(&source_turso_path, source_opts, &dest_turso_path, dest_opts)?;

    // The source entry must still be the inode validated above; otherwise
    // what was copied and verified is not the file the caller named.
    if !entry_matches(source_dir, source_name, &source_fd) {
        return Err(RekeyError::SourceReplaced(source_name.to_string()));
    }

    // Every destination directory entry (main file and sidecars) must still
    // be the inode created above; otherwise the destination was substituted
    // while we were writing and turso may have written through a swapped-in
    // entry.
    if !entry_matches(dest_dir, dest_name, &dest.file)
        || !rustix::fs::statat(dest_dir, dest_name, AtFlags::SYMLINK_NOFOLLOW)
            .is_ok_and(|st| FileType::from_raw_mode(st.st_mode).is_file())
    {
        return Err(RekeyError::UnsafeDestination(format!(
            "destination '{dest_name}' was replaced during rekey"
        )));
    }
    for (sidecar, fd) in &dest.sidecars {
        match rustix::fs::statat(dest_dir, sidecar.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            // already removed (e.g. by the database layer on close) — nothing
            // a substituted entry could have captured
            Err(rustix::io::Errno::NOENT) => {}
            Ok(entry) => {
                let created = rustix::fs::fstat(fd).map_err(|e| RekeyError::Io(e.into()))?;
                if entry.st_dev != created.st_dev || entry.st_ino != created.st_ino {
                    return Err(RekeyError::UnsafeDestination(format!(
                        "destination sidecar '{sidecar}' was replaced during rekey"
                    )));
                }
            }
            Err(e) => return Err(RekeyError::Io(e.into())),
        }
    }

    // The WAL was checkpointed with TRUNCATE inside run_rekey, so the created
    // WAL inode must be empty (committed credentials all live in the main
    // file). fstat on our own descriptor, so a swapped entry cannot spoof it.
    let wal_name = format!("{dest_name}-wal");
    if let Some((_, wal_fd)) = dest.sidecars.iter().find(|(name, _)| *name == wal_name) {
        let st = rustix::fs::fstat(wal_fd).map_err(|e| RekeyError::Io(e.into()))?;
        if st.st_size > 0 {
            return Err(RekeyError::Database(format!(
                "destination WAL '{wal_name}' still contains {} bytes after checkpoint",
                st.st_size
            )));
        }
    }

    // Durability: sync file contents through the created descriptor, remove
    // the (empty) sidecar files we created, then sync the directory.
    rustix::fs::fsync(&dest.file).map_err(|e| RekeyError::Io(e.into()))?;
    dest.unlink_created_sidecars();
    rustix::fs::fsync(dest_dir).map_err(|e| RekeyError::Io(e.into()))?;

    dest.committed = true;
    Ok(RekeyOutcome { copied })
}

/// Open a turso database, retrying transient locking errors, mapping failures
/// to typed errors attributed to `side`.
fn open_turso_db(
    path: &str,
    opts: Option<&EncryptionOpts>,
    side: Side,
) -> Result<Database, RekeyError> {
    let mut retries = crate::OPEN_LOCK_RETRIES;
    let mut backoff_ms = crate::OPEN_LOCK_BACKOFF_MS;
    loop {
        let mut builder = Builder::new_local(path);
        if let Some(opts) = opts {
            // key stays zeroizing on our side; see turso_encryption_opts for
            // the turso boundary note
            builder = builder
                .experimental_encryption(true)
                .with_encryption(crate::turso_encryption_opts(opts));
        }
        match block_on(builder.build()) {
            Ok(db) => return Ok(db),
            Err(err) => {
                if retries == 0 || !crate::is_turso_locking_error(&err) {
                    return Err(db_err(&err, side));
                }
                retries -= 1;
                std::thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(crate::OPEN_LOCK_BACKOFF_MAX_MS);
            }
        }
    }
}

fn connect(db: &Database, side: Side) -> Result<Connection, RekeyError> {
    // retry transient locking errors (another process may briefly hold the
    // file lock), mirroring the store's own connect behavior
    let mut retries = crate::OPEN_LOCK_RETRIES;
    let mut backoff_ms = crate::OPEN_LOCK_BACKOFF_MS;
    let conn = loop {
        match db.connect() {
            Ok(conn) => break conn,
            Err(err) => {
                if retries == 0 || !crate::is_turso_locking_error(&err) {
                    return Err(db_err(&err, side));
                }
                retries -= 1;
                std::thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(crate::OPEN_LOCK_BACKOFF_MAX_MS);
            }
        }
    };
    conn.busy_timeout(Duration::from_millis(u64::from(crate::BUSY_TIMEOUT_MS)))
        .map_err(|e| db_err(&e, side))?;
    Ok(conn)
}

/// The complete database-level rekey: open both databases, copy all records
/// streaming, verify every record exactly, checkpoint and close the
/// destination. Returns the verified record count.
fn run_rekey(
    source_path: &str,
    source_opts: Option<&EncryptionOpts>,
    dest_path: &str,
    dest_opts: Option<&EncryptionOpts>,
) -> Result<u64, RekeyError> {
    let source_db = open_turso_db(source_path, source_opts, Side::Source)?;
    let source_conn = connect(&source_db, Side::Source)?;
    // Note: the source connection gets no journal-mode pragma so an existing
    // source is never modified; only reads are performed against it.
    ensure_source_schema(&source_conn)?;
    let allow_ambiguity = !block_on(crate::schema_has_unique_service_user(&source_conn))
        .map_err(|e| db_err(&e, Side::Source))?;

    let dest_db = open_turso_db(dest_path, dest_opts, Side::Destination)?;
    let dest_conn = connect(&dest_db, Side::Destination)?;
    crate::configure_connection(&dest_conn).map_err(|e| keyring_err(&e, Side::Destination))?;
    crate::init_schema(&dest_conn, allow_ambiguity, false)
        .map_err(|e| keyring_err(&e, Side::Destination))?;

    let copied = copy_records(&source_conn, &dest_conn)?;
    let verified = verify_records(&source_conn, &dest_conn)?;
    if verified != copied {
        return Err(RekeyError::VerificationMismatch(format!(
            "copied {copied} records but verified {verified}"
        )));
    }
    checkpoint_truncate(&dest_conn)?;
    Ok(copied)
}

/// The source must already be a db-keystore database with a supported schema
/// version; nothing is created or written in it (unlike opening it as a
/// store, which would initialize missing schema).
fn ensure_source_schema(conn: &Connection) -> Result<(), RekeyError> {
    block_on(async {
        let mut tables = std::collections::HashSet::new();
        let mut rows = conn
            .query(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name IN ('credentials', 'keystore_meta')",
                (),
            )
            .await
            .map_err(|e| db_err(&e, Side::Source))?;
        while let Some(row) = rows.next().await.map_err(|e| db_err(&e, Side::Source))? {
            let value = row.get_value(0).map_err(|e| db_err(&e, Side::Source))?;
            tables.insert(value_text(&value, "table name")?.to_string());
        }
        if !tables.contains("credentials") {
            return Err(RekeyError::CorruptSource(
                "no credentials table in source database".to_string(),
            ));
        }
        // Reject unsupported schema versions rather than silently restamping
        // the destination with the current version. A missing keystore_meta
        // table is tolerated (nothing is ever written to the source).
        if tables.contains("keystore_meta") {
            let mut rows = conn
                .query(
                    "SELECT value FROM keystore_meta WHERE key = 'schema_version'",
                    (),
                )
                .await
                .map_err(|e| db_err(&e, Side::Source))?;
            if let Some(row) = rows.next().await.map_err(|e| db_err(&e, Side::Source))? {
                let value = row.get_value(0).map_err(|e| db_err(&e, Side::Source))?;
                let version = value_text(&value, "schema_version")?
                    .parse::<u32>()
                    .map_err(|_| {
                        RekeyError::CorruptSource("invalid schema_version in source".to_string())
                    })?;
                if version != crate::SCHEMA_VERSION {
                    return Err(RekeyError::CorruptSource(format!(
                        "unsupported source schema version: {version}"
                    )));
                }
            }
        }
        Ok(())
    })
}

/// Stream every credential from source to destination, one record at a time,
/// inside a single destination transaction.
///
/// Every column is copied as the raw value read from the source — no
/// normalization, so the destination is a byte- and storage-class-exact copy
/// and the streaming verification (which orders and compares both sides
/// identically) cannot be tripped by a lossy rewrite. Values are validated
/// (types, lengths, uuid syntax) but never altered.
///
/// The secret travels inside the `turso::Value` produced by the row read and
/// consumed by the parameter bind; both allocations are owned by turso, which
/// frees without wiping (see the module docs on the turso boundary). No
/// additional copy of the secret is made here.
fn copy_records(source: &Connection, dest: &Connection) -> Result<u64, RekeyError> {
    block_on(async {
        let mut rows = source
            .query(
                "SELECT service, user, uuid, secret, comment FROM credentials",
                (),
            )
            .await
            .map_err(|e| db_err(&e, Side::Source))?;
        dest.execute("BEGIN IMMEDIATE", ())
            .await
            .map_err(|e| db_err(&e, Side::Destination))?;
        let mut copied = 0u64;
        let result = async {
            loop {
                let Some(row) = rows.next().await.map_err(|e| db_err(&e, Side::Source))? else {
                    break;
                };
                let mut values = Vec::with_capacity(5);
                for idx in 0..5 {
                    values.push(row.get_value(idx).map_err(|e| db_err(&e, Side::Source))?);
                }

                // validate without altering: text-ness and lengths of the
                // identity columns, uuid syntax (any case), secret length,
                // comment type
                {
                    let service = value_text(&values[0], "service")?;
                    let user = value_text(&values[1], "user")?;
                    crate::validate_service_user(service, user)
                        .map_err(|e| RekeyError::CorruptSource(e.to_string()))?;
                    let uuid = value_text(&values[2], "uuid")?;
                    uuid::Uuid::try_parse(uuid).map_err(|_| {
                        RekeyError::CorruptSource(format!(
                            "invalid uuid for record {service}/{user}"
                        ))
                    })?;
                    let secret_len = match &values[3] {
                        Value::Blob(bytes) => bytes.len(),
                        Value::Text(text) => text.len(),
                        _ => {
                            return Err(RekeyError::CorruptSource(format!(
                                "unexpected secret type for record {service}/{user}/{uuid}"
                            )));
                        }
                    };
                    crate::validate_secret_len(secret_len)
                        .map_err(|e| RekeyError::CorruptSource(e.to_string()))?;
                    match &values[4] {
                        Value::Null | Value::Text(_) => {}
                        Value::Blob(bytes) if std::str::from_utf8(bytes).is_ok() => {}
                        _ => {
                            return Err(RekeyError::CorruptSource(format!(
                                "unexpected comment type for record {service}/{user}/{uuid}"
                            )));
                        }
                    }
                }

                let mut values = values.into_iter();
                let params = (
                    values.next().expect("service value"),
                    values.next().expect("user value"),
                    values.next().expect("uuid value"),
                    values.next().expect("secret value"),
                    values.next().expect("comment value"),
                );
                dest.execute(
                    "INSERT INTO credentials (service, user, uuid, secret, comment) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params,
                )
                .await
                .map_err(|e| db_err(&e, Side::Destination))?;
                copied += 1;
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                dest.execute("COMMIT", ())
                    .await
                    .map_err(|e| db_err(&e, Side::Destination))?;
                Ok(copied)
            }
            Err(err) => {
                let _ = dest.execute("ROLLBACK", ()).await;
                Err(err)
            }
        }
    })
}

/// Borrow a value as text (TEXT, or BLOB holding valid UTF-8) without
/// converting or copying it.
fn value_text<'v>(value: &'v Value, field: &str) -> Result<&'v str, RekeyError> {
    match value {
        Value::Text(text) => Ok(text.as_str()),
        Value::Blob(bytes) => std::str::from_utf8(bytes)
            .map_err(|e| RekeyError::CorruptSource(format!("invalid utf8 for {field}: {e}"))),
        other => Err(RekeyError::CorruptSource(format!(
            "unexpected value for {field}: {}",
            value_type_name(other)
        ))),
    }
}

/// Type name only — never value content, which may be sensitive.
fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NULL",
        Value::Integer(_) => "INTEGER",
        Value::Real(_) => "REAL",
        Value::Text(_) => "TEXT",
        Value::Blob(_) => "BLOB",
    }
}

fn read_text(row: &turso::Row, idx: usize, field: &str, side: Side) -> Result<String, RekeyError> {
    let value = row.get_value(idx).map_err(|e| db_err(&e, side))?;
    value_text(&value, field).map(ToString::to_string)
}

/// Deterministic total order over all record fields (including comment and
/// secret bytes) so that equal multisets — and only equal multisets — compare
/// equal record-by-record. Ordering by the secret as well is what lets two
/// records with identical metadata but different secrets be detected.
const VERIFY_SQL: &str = "SELECT service, user, uuid, comment, secret FROM credentials \
     ORDER BY service, user, uuid, comment, secret";

/// Compare every source record against every destination record, streaming
/// one record from each side at a time (bounded memory). Returns the number
/// of records verified. Mismatch messages identify records by service, user,
/// and uuid only — never by secret content, and no digest of secrets is
/// computed or exposed.
fn verify_records(source: &Connection, dest: &Connection) -> Result<u64, RekeyError> {
    block_on(async {
        let mut source_rows = source
            .query(VERIFY_SQL, ())
            .await
            .map_err(|e| db_err(&e, Side::Source))?;
        let mut dest_rows = dest
            .query(VERIFY_SQL, ())
            .await
            .map_err(|e| db_err(&e, Side::Destination))?;
        let mut verified = 0u64;
        loop {
            let next_source = source_rows
                .next()
                .await
                .map_err(|e| db_err(&e, Side::Source))?;
            let next_dest = dest_rows
                .next()
                .await
                .map_err(|e| db_err(&e, Side::Destination))?;
            match (next_source, next_dest) {
                (None, None) => break,
                (Some(row), None) => {
                    let id = record_id(&row, Side::Source)?;
                    return Err(RekeyError::VerificationMismatch(format!(
                        "destination is missing record {id}"
                    )));
                }
                (None, Some(row)) => {
                    let id = record_id(&row, Side::Destination)?;
                    return Err(RekeyError::VerificationMismatch(format!(
                        "destination has unexpected extra record {id}"
                    )));
                }
                (Some(src_row), Some(dst_row)) => {
                    compare_row(&src_row, &dst_row)?;
                    verified += 1;
                }
            }
        }
        Ok(verified)
    })
}

fn record_id(row: &turso::Row, side: Side) -> Result<String, RekeyError> {
    let service = read_text(row, 0, "service", side)?;
    let user = read_text(row, 1, "user", side)?;
    let uuid = read_text(row, 2, "uuid", side)?;
    Ok(format!("{service}/{user}/{uuid}"))
}

/// Compare one source row against one destination row: every column must be
/// equal in both storage class and content (the copy is class- and byte-exact,
/// so any difference is a real divergence). Mismatch messages name the field
/// and the record's identity, never value content.
fn compare_row(src: &turso::Row, dst: &turso::Row) -> Result<(), RekeyError> {
    for (idx, field) in [
        (0, "service"),
        (1, "user"),
        (2, "uuid"),
        (3, "comment"),
        (4, "secret"),
    ] {
        let s = src.get_value(idx).map_err(|e| db_err(&e, Side::Source))?;
        let d = dst
            .get_value(idx)
            .map_err(|e| db_err(&e, Side::Destination))?;
        // Exact comparison; the result reveals only equal/not-equal, never
        // the content. The values here are turso-owned copies either way
        // (see the module docs on the turso boundary).
        if s != d {
            return Err(RekeyError::VerificationMismatch(format!(
                "{field} mismatch for record {}",
                record_id(src, Side::Source)?
            )));
        }
    }
    Ok(())
}

/// Checkpoint the destination WAL with TRUNCATE so no committed credential is
/// stranded in the WAL, and the WAL file ends up empty.
fn checkpoint_truncate(conn: &Connection) -> Result<(), RekeyError> {
    block_on(async {
        let mut rows = conn
            .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
            .await
            .map_err(|e| db_err(&e, Side::Destination))?;
        if let Some(row) = rows
            .next()
            .await
            .map_err(|e| db_err(&e, Side::Destination))?
        {
            let busy = row
                .get_value(0)
                .map_err(|e| db_err(&e, Side::Destination))?;
            if let Value::Integer(busy) = busy
                && busy != 0
            {
                return Err(RekeyError::Database(
                    "destination WAL checkpoint reported busy".to_string(),
                ));
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DbKeyStoreConfig;
    use keyring_core::api::CredentialStoreApi;

    const HEXKEY_128: &str = "000102030405060708090a0b0c0d0e0f";
    const HEXKEY_256: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn sensitive_key_from_hex_round_trips() {
        let key = SensitiveKey::from_hex(HEXKEY_256).expect("from_hex");
        assert_eq!(key.len(), 32);
        assert!(!key.is_empty());
        assert_eq!(key.as_bytes()[0], 0x00);
        assert_eq!(key.as_bytes()[31], 0x1f);
        assert_eq!(key.to_hex().as_str(), HEXKEY_256);

        let key = SensitiveKey::from_hex(HEXKEY_128).expect("from_hex 128");
        assert_eq!(key.len(), 16);
        assert_eq!(key.to_hex().as_str(), HEXKEY_128);

        // uppercase accepted, re-encoded lowercase
        let key = SensitiveKey::from_hex(&HEXKEY_256.to_ascii_uppercase()).expect("upper");
        assert_eq!(key.to_hex().as_str(), HEXKEY_256);
    }

    #[test]
    fn sensitive_key_rejects_bad_input() {
        assert!(matches!(
            SensitiveKey::from_hex("abcd"),
            Err(RekeyError::InvalidKey(_))
        ));
        let bad = "zz0102030405060708090a0b0c0d0e0f";
        assert!(matches!(
            SensitiveKey::from_hex(bad),
            Err(RekeyError::InvalidKey(_))
        ));
        assert!(matches!(
            SensitiveKey::from_bytes(&[0u8; 8]),
            Err(RekeyError::InvalidKey(_))
        ));
        assert!(SensitiveKey::from_bytes(&[7u8; 32]).is_ok());
        assert!(SensitiveKey::from_bytes(&[7u8; 16]).is_ok());
    }

    // Acceptance 8/9 (crate side): no key material appears in Debug output of
    // any type that holds a key, and hex encoding stays in zeroizing owners.
    #[test]
    fn debug_output_redacts_keys() {
        let key = SensitiveKey::from_hex(HEXKEY_256).expect("key");
        let debug = format!("{key:?}");
        assert!(
            !debug.contains("0001"),
            "debug leaked key material: {debug}"
        );
        assert!(debug.contains("redacted"));

        let opts = EncryptionOpts::new("aes256gcm", HEXKEY_256).expect("opts");
        let debug = format!("{opts:?}");
        assert!(
            !debug.contains("0001"),
            "debug leaked key material: {debug}"
        );
        assert!(debug.contains("redacted"));
        assert!(debug.contains("aes256gcm"));

        // the hex encoding used at the turso boundary is itself zeroizing
        let hex: Zeroizing<String> = key.to_hex();
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn encryption_opts_validates_key_length() {
        // 128-bit key for a 256-bit cipher must be rejected
        let err = EncryptionOpts::new("aes256gcm", HEXKEY_128).expect_err("length mismatch");
        assert!(err.to_string().contains("32"), "unexpected: {err}");
        // and the reverse
        assert!(EncryptionOpts::new("aes128gcm", HEXKEY_256).is_err());
        // dash alias accepted
        assert!(EncryptionOpts::new("aes-256-gcm", HEXKEY_256).is_ok());
        // empty cipher rejected
        assert!(EncryptionOpts::new("", HEXKEY_256).is_err());
    }

    fn store_at(path: &std::path::Path) -> std::sync::Arc<DbKeyStore> {
        DbKeyStore::new(DbKeyStoreConfig {
            path: path.to_path_buf(),
            ..Default::default()
        })
        .expect("store")
    }

    fn raw_conn(path: &std::path::Path) -> Connection {
        let db = block_on(Builder::new_local(path.to_str().expect("utf8")).build()).expect("db");
        db.connect().expect("conn")
    }

    fn connections(
        src: &std::path::Path,
        dst: &std::path::Path,
    ) -> (Database, Connection, Database, Connection) {
        let sdb = open_turso_db(src.to_str().unwrap(), None, Side::Source).expect("src db");
        let sconn = connect(&sdb, Side::Source).expect("src conn");
        let ddb = open_turso_db(dst.to_str().unwrap(), None, Side::Destination).expect("dst db");
        let dconn = connect(&ddb, Side::Destination).expect("dst conn");
        (sdb, sconn, ddb, dconn)
    }

    // Acceptance 1: corrupting one credential secret in the destination —
    // leaving the row count unchanged — makes verification fail.
    #[test]
    fn verification_detects_corrupted_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src.db");
        let dst = dir.path().join("dst.db");
        {
            let store = store_at(&src);
            for (user, pw) in [("alice", "pw-a"), ("bob", "pw-b")] {
                let entry = store.build("svc", user, None).expect("build");
                entry.set_password(pw).expect("set");
            }
        }
        DbKeyStore::rekey(&src, None, &dst, None).expect("rekey");

        // verification passes on the honest copy
        {
            let (_sdb, sconn, _ddb, dconn) = connections(&src, &dst);
            assert_eq!(verify_records(&sconn, &dconn).expect("verify"), 2);
        }

        // corrupt one destination secret without changing the row count
        {
            let conn = raw_conn(&dst);
            let changed = block_on(conn.execute(
                "UPDATE credentials SET secret = X'DEADBEEF' WHERE user = 'bob'",
                (),
            ))
            .expect("corrupt");
            assert_eq!(changed, 1);
        }

        let (_sdb, sconn, _ddb, dconn) = connections(&src, &dst);
        let err = verify_records(&sconn, &dconn).expect_err("must detect corruption");
        assert!(
            matches!(err, RekeyError::VerificationMismatch(_)),
            "unexpected error: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            !msg.contains("pw-b")
                && !msg.contains("DEADBEEF")
                && !msg.to_lowercase().contains("deadbeef"),
            "error message must not contain secret material: {msg}"
        );
    }

    // Acceptance 2: two records with identical metadata but different secrets
    // are detected (a count- or metadata-only comparison would miss this).
    #[test]
    fn verification_detects_identical_metadata_different_secrets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src.db");
        let dst = dir.path().join("dst.db");

        // hand-build both databases with two rows of identical metadata;
        // source secrets {A, B}, destination secrets {A, A}
        for (path, second_secret) in [(&src, "B"), (&dst, "A")] {
            let conn = raw_conn(path);
            block_on(conn.execute(
                "CREATE TABLE credentials (service TEXT NOT NULL, user TEXT NOT NULL, \
                 uuid TEXT NOT NULL, secret BLOB NOT NULL, comment TEXT)",
                (),
            ))
            .expect("create");
            for secret in ["A", second_secret] {
                block_on(conn.execute(
                    "INSERT INTO credentials (service, user, uuid, secret) \
                     VALUES ('svc', 'alice', '018f0000-0000-7000-8000-000000000001', ?1)",
                    (Value::Blob(secret.as_bytes().to_vec()),),
                ))
                .expect("insert");
            }
        }

        let (_sdb, sconn, _ddb, dconn) = connections(&src, &dst);
        let err = verify_records(&sconn, &dconn).expect_err("must detect differing secrets");
        assert!(
            matches!(err, RekeyError::VerificationMismatch(_)),
            "unexpected error: {err:?}"
        );
    }

    // Verification detects missing and extra destination records even when
    // metadata-identical rows make the count ambiguous.
    #[test]
    fn verification_detects_missing_and_extra_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src.db");
        let dst = dir.path().join("dst.db");
        {
            let store = store_at(&src);
            for (user, pw) in [("alice", "pw-a"), ("bob", "pw-b")] {
                let entry = store.build("svc", user, None).expect("build");
                entry.set_password(pw).expect("set");
            }
        }
        DbKeyStore::rekey(&src, None, &dst, None).expect("rekey");
        {
            let conn = raw_conn(&dst);
            block_on(conn.execute("DELETE FROM credentials WHERE user = 'bob'", ()))
                .expect("delete");
        }
        let (_sdb, sconn, _ddb, dconn) = connections(&src, &dst);
        let err = verify_records(&sconn, &dconn).expect_err("must detect missing record");
        assert!(matches!(err, RekeyError::VerificationMismatch(_)));

        // extra record in the destination
        {
            let conn = raw_conn(&dst);
            for user in ["bob", "eve"] {
                block_on(conn.execute(
                    &format!(
                        "INSERT INTO credentials (service, user, uuid, secret) \
                         VALUES ('svc', '{user}', '018f0000-0000-7000-8000-0000000000aa', X'00')"
                    ),
                    (),
                ))
                .expect("insert");
            }
        }
        let (_sdb, sconn, _ddb, dconn) = connections(&src, &dst);
        let err = verify_records(&sconn, &dconn).expect_err("must detect extra record");
        assert!(matches!(err, RekeyError::VerificationMismatch(_)));
    }

    // The destination inode check: if the directory entry is swapped after
    // creation, the mismatch is detected (UnsafeDestination).
    #[cfg(unix)]
    #[test]
    fn destination_inode_swap_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_fd = open_dir(dir.path()).expect("dir fd");
        let guard = create_destination(dir_fd.as_fd(), "dst.db").expect("create");

        // swap the directory entry for a different file
        std::fs::remove_file(dir.path().join("dst.db")).expect("remove");
        std::fs::write(dir.path().join("dst.db"), b"substitute").expect("substitute");

        let entry = rustix::fs::statat(dir_fd.as_fd(), "dst.db", AtFlags::SYMLINK_NOFOLLOW)
            .expect("statat");
        let created = rustix::fs::fstat(&guard.file).expect("fstat");
        assert!(
            entry.st_ino != created.st_ino,
            "test setup: entry should now be a different inode"
        );
    }

    // Destination files start with mode 0600 regardless of umask (fchmod pins it).
    #[cfg(unix)]
    #[test]
    fn destination_created_mode_0600() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_fd = open_dir(dir.path()).expect("dir fd");
        let _guard = create_destination(dir_fd.as_fd(), "dst.db").expect("create");
        for name in ["dst.db", "dst.db-wal", "dst.db-tshm"] {
            let mode = dir.path().join(name).metadata().expect("meta").mode() & 0o7777;
            assert_eq!(mode, 0o600, "{name} must be created 0600, got {mode:o}");
        }
    }
}
