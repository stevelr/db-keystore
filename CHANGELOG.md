# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## 0.5.0-pre.1

New rekey API - moved from cli to library for reusability by external crates,
and added verification and additional integrity controls.
Database must be quiescent for rekey operation.
See README.md for hardening best practice.

**Highlights**

- After rekey, every entry in destination is verified. In 0.4.x only the number
  of entries was verified.
- Fix: Source with invalid `schema_version` is rejected after read-only check.
  In 0.4.x rekey cli, file was not opened read-only and could have initialized schema in it.

**BREAKING**: `EncryptionOpts` fields are now private; the key is decoded from
hex at construction into a `SensitiveKey` (wiped on drop) instead of being
stored as an ordinary `String`. `EncryptionOpts::new(&str, &str)` borrows
its arguments, validates the hex and its length against the cipher, and
returns `Result`. Hex re-encoding for the database layer happens in a
zeroizing buffer.

**Added**

- `DbKeyStore::rekey` rekey api. `rekey` does not run schema initialization against the
  source, so a failed rekey can never modify the source database (the source
  connection also no longer sets a persistent journal mode).
- Failed rekeys clean up the partial destination, but only files whose
  directory entries still match the inodes rekey itself created; pre-existing
  or substituted files (including WAL/SHM sidecars) are rejected with
  `DestinationExists`/`UnsafeDestination` and never deleted.
- `SensitiveKey`: fixed-size zeroizing DEK container (`Zeroizing<[u8; 32]>`,
  supports 128- and 256-bit keys). Constructors borrow caller-owned buffers
  (`from_hex(&str)`, `from_bytes(&[u8])`), so callers are not required to use
  any particular zeroizing library; accessors return internal references.
- `RekeyError`: typed error enum for rekey (`WrongSourceKey`,
  `CorruptSource`, `VerificationMismatch`, `DestinationExists`,
  `UnsafeDestination`, `SourceReplaced`, `Panicked`, ...). Wrong-key and
  malformed-database cases return errors and never panic (confirmed by test:
  turso 0.7 returns `Err` on a wrong key; rekey additionally wraps the
  operation in `catch_unwind` as defense in depth).
- `rekey_at` (Linux): descriptor-relative rekey. Source and destination are
  named relative to caller-owned directory descriptors; the destination and
  its WAL/SHM sidecars are created with `openat` + `O_CREAT | O_EXCL |
  O_NOFOLLOW`, mode `0600` from the instant of creation (`fchmod` pins it
  against the umask), and the databases are opened through
  `/proc/self/fd/<dirfd>/<name>` so directory substitution cannot redirect
  any file turso touches. Before success, every directory entry (source,
  destination, sidecars) is re-checked against the inode validated or created
  at the start; a final-component swap in the window before turso's by-path
  open is thereby detected (turso cannot yet open an already-created
  descriptor, so it cannot be prevented outright — see module docs).
- Exact rekey verification: `DbKeyStore::rekey` does not return success until
  every record (`service`, `user`, `uuid`, `comment`, and secret bytes) has
  been compared between source and destination, streaming one record at a
  time (bounded memory). Records are copied byte- and storage-class-exact —
  no case-folding, comment normalization, or type coercion — so verification
  compares raw values for strict equality. A matching row count alone is
  never accepted, and there is no `verified` flag to ignore — success means
  verified. No digest of secrets (keyed or otherwise) is computed, persisted,
  or returned.
- Durable close: before returning success the destination WAL is checkpointed
  (`TRUNCATE`), the file and its directory are fsynced, WAL/SHM sidecar files
  are removed, and the WAL/SHM sidecars are pre-created with mode `0600` so
  credential plaintext in the WAL is never world-readable.
- Acceptance tests for the above in `tests/rekey.rs` and `src/rekey.rs`,
  including: secret corruption with unchanged row count fails; identical
  metadata with different secrets is detected; uncheckpointed source WAL
  transactions are copied; wrong/missing source keys error without panic;
  existing files and symlinks (including dangling) are rejected; destination
  is created `0600`; an interrupted rekey removes the partial destination and
  leaves the source unchanged and usable.

**Known limitation**

- turso 0.7 caches unencrypted pages, and does not zeroize encryption key
  (stored as `String`) or decrypted blobs (`Vec<u8`). While all buffers in
  db-keystore are zeroized, we don't have control of the turso side of
  the api boundary.

## 0.4.4

**Added**

- Public rekey api `DbKeyStore::rekey`. Moved functionality from cli to library
  so it can be used programmatically.
  Use to change encryption key, add encryption, or remove encryption.
  Requires quiescent database.

**Changed**

- Bumped turso dependency from 0.6.1 to 0.7.0

## [0.4.3]

**Changed**

- bump turso -> 0.6.1
- improved build speed and size by disabling turso full-text-search (was not used by db-keystore). [See turso 6478](https://github.com/tursodatabase/turso/issues/6478) (215 deps -> 157 deps)

## [0.4.2-pre.2]

- bump turso -> 0.6.0-pre.22; keyring-core -> 1.0.0

## [0.4.2-pre.1]

- bump dependencies: turso ->0.5.3, clap 4.5.60->4.6.1, tempfile 3.25.0->3.27.0, uuid->1.22.0, keyring-core 0.7.2->0.7.4, other patch updates
- bump to turso 0.5.3 fixes #6 (panic on incorrect decryption key)

## [0.4.1]

This version upgrades turso db to fix the panic when opening an encrypted db with the wrong key. Attempting to open with an incorrect encryption key causes `new` or `new_with_modifiers` to fail with NoStorageAccess.

### Changed

- upgrade turso from 0.4.4 to 0.5.0-pre.8
- unpinned uuid dependency (was pinned to 1.20.0)
- bumped tempfile to 3.25

## [0.4.0] - 2026-02-02

### Breaking

- `DbKeyStore::new` requires `DbKeyStoreConfig` instead of `&DbKeyStoreConfig`.
- All input uuids are converted to lowercase and checked for uuid syntax, returning Error::Invalid for incorrect format.

### Added

- binary db-keystore maintenance/admin utility
- added msrv declaration (1.88)
- bumped turso dependency to 0.4.4

### Changed

- Changed uuid generation from v4 to v7 so ambiguous entries can be sorted by creation time (only applies to automatically inserted uuids, which are generated with uuid::now_v7()).
- Empty comment strings are normalized to NULL on insert/update; comment search with empty string now matches NULL/empty comments only.
- Use zeroize internally to prevent secrets from leaking into heap
- moved dump-db-keystore to examples

### Fixed

- Scoped uuid-based operations to `service` and `user` to avoid cross-credential collisions when uuids are not unique. (Uuid collisions are still very unlikely).

### Documentation

- Updated README and examples.

## [0.3.1] - 2026-01-28

### Added

- Allow `build` modifiers `uuid` and `comment`, enabling explicit UUID creation and initial comment storage.
- New tests for ambiguity handling, shared credentials, in-memory store round-trip, and comment modifiers.
- Documentation for vfs options
- Added impl Debug for DbKeyStore

### Changed

- Modifier/spec validation now uses `parse_attributes`, including boolean parsing.
- Consolidated credential fetch queries to reduce duplication.
- Updated docs to describe `index-always` and build modifiers.
- Clarified that memory vfs ignores path and encryption keys.

### Breaking

- `new` returns `Result<Arc<DbKeyStore>>` instead of `Result<DbKeyStore>`
- `delete_credential` now returns `NoEntry` when no matching credential exists (was idempotent and returned Ok).

## [0.3.0] - 2026-01-27

### Changed

- `new_with_modifiers` returns `Result<Arc<DbKeyStore>>` instead of `Result<DbKeyStore>`

  This may or may not be a breaking change, depending on how it's used. Bumping minor version to follow strict semver.

## [0.2.2] - 2026-01-25

### Added

- Improved documentation and added examples
- Added DbKeyStore getters `path()` and `is_encrypted()`
- Added `encrypted` and `path` fields to inner struct so they appear in Debug and Display impl
- Added `dump-db-keystore` debugging utility (bin/)
- Added schema version metadata table for future migrations

### Changed

- Added crate version and enc:bool to DbKeyStore `id()` response
- Exported `default_path()` as a public function
- Secrets no longer restricted to UTF-8 text - any bytes up to max length supported
- Clearer controls for performance and stress tests

### Fixed

- `dump-db-keystore` now honors `path=...` arguments
- Encrypted example now reopens with the correct key
- Stress test children remove temp database files when temp dir is provided

## [0.2.0] - 2026-01-20

- initial github release
