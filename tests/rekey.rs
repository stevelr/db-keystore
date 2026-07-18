//! Acceptance tests for the verified, safely-created rekey API.
//! (See todo/CHANGELOG for the release contract these prove.)

use std::collections::HashMap;
use std::path::Path;

use db_keystore::{DbKeyStore, DbKeyStoreConfig, EncryptionOpts, RekeyError};
use futures::executor::block_on;
use keyring_core::api::CredentialStoreApi;
use zeroize::Zeroizing;

const HEXKEY_256: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
// distinct N+1 key for rotation tests
const HEXKEY_256_B: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
// a third key, wrong for everything
const HEXKEY_256_WRONG: &str = "1230000011111111222222223333333344444444555555556666666677777777";

fn enc_opts(hexkey: &str) -> EncryptionOpts {
    EncryptionOpts::new("aes256gcm", hexkey).expect("encryption opts")
}

fn open_encrypted(path: &Path, hexkey: &str) -> DbKeyStore {
    let config = DbKeyStoreConfig {
        path: path.to_path_buf(),
        encryption_opts: Some(enc_opts(hexkey)),
        ..Default::default()
    };
    (*DbKeyStore::new(config).expect("open encrypted store")).clone()
}

fn open_plain(path: &Path) -> DbKeyStore {
    let config = DbKeyStoreConfig {
        path: path.to_path_buf(),
        ..Default::default()
    };
    (*DbKeyStore::new(config).expect("open store")).clone()
}

fn password_of(store: &DbKeyStore, service: &str, user: &str) -> String {
    let results = store
        .search(&HashMap::from([("service", service), ("user", user)]))
        .expect("search");
    assert_eq!(results.len(), 1, "expected exactly one {service}/{user}");
    Zeroizing::new(results[0].get_password().expect("get_password"))
        .as_str()
        .to_string()
}

fn assert_no_sidecars(path: &Path) {
    let base = path.to_str().expect("utf8 path");
    for suffix in ["-wal", "-tshm", "-shm"] {
        let sidecar = format!("{base}{suffix}");
        assert!(
            !Path::new(&sidecar).exists(),
            "sidecar file {sidecar} should not remain after rekey"
        );
    }
}

#[cfg(unix)]
fn assert_mode_0600(path: &Path) {
    use std::os::unix::fs::MetadataExt;
    let mode = path.metadata().expect("metadata").mode() & 0o7777;
    assert_eq!(mode, 0o600, "destination must be mode 0600, got {mode:o}");
}

// Acceptance: rotate-dek N -> N+1. Every credential decrypts under the new
// key and matches the source; the source remains readable under the old key;
// the destination is cleanly closed (no WAL/SHM), mode 0600; the wrong
// destination key fails closed with an error and never panics.
#[test]
fn rekey_rotates_dek_out_of_place() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("seq-n.db");
    let dst = dir.path().join("seq-n+1.db");

    {
        let store = open_encrypted(&src, HEXKEY_256);
        for (svc, user, pw) in [("svc-a", "alice", "pw-a"), ("svc-b", "bob", "pw-b")] {
            let entry = store.build(svc, user, None).expect("build");
            entry.set_password(pw).expect("set_password");
        }
        let commented = store
            .build(
                "svc-c",
                "carol",
                Some(&HashMap::from([("comment", "note-c")])),
            )
            .expect("build commented");
        commented.set_password("pw-c").expect("set_password");
    }

    let outcome = DbKeyStore::rekey(
        &src,
        Some(&enc_opts(HEXKEY_256)),
        &dst,
        Some(&enc_opts(HEXKEY_256_B)),
    )
    .expect("rekey");
    assert_eq!(outcome.copied, 3, "all three credentials copied");
    assert!(src.is_file(), "source left intact");
    assert!(dst.is_file(), "destination written");
    assert_no_sidecars(&dst);
    #[cfg(unix)]
    assert_mode_0600(&dst);

    // destination decrypts under the NEW key and matches the source values
    {
        let store = open_encrypted(&dst, HEXKEY_256_B);
        assert_eq!(password_of(&store, "svc-a", "alice"), "pw-a");
        assert_eq!(password_of(&store, "svc-b", "bob"), "pw-b");
        assert_eq!(password_of(&store, "svc-c", "carol"), "pw-c");
        let results = store
            .search(&HashMap::from([("service", "svc-c"), ("user", "carol")]))
            .expect("search");
        let attrs = results[0].get_attributes().expect("get_attributes");
        assert_eq!(attrs.get("comment"), Some(&"note-c".to_string()));
        assert!(attrs.contains_key("uuid"));
    }

    // source still readable under the OLD key
    {
        let store = open_encrypted(&src, HEXKEY_256);
        assert_eq!(password_of(&store, "svc-a", "alice"), "pw-a");
    }

    // wrong destination key fails closed (no plaintext leak, no panic)
    {
        let config = DbKeyStoreConfig {
            path: dst.clone(),
            encryption_opts: Some(enc_opts(HEXKEY_256)),
            ..Default::default()
        };
        let result = std::panic::catch_unwind(|| DbKeyStore::new(config));
        assert!(
            matches!(result, Ok(Err(_))),
            "opening rekeyed db with the old (wrong) key must return an error without panicking"
        );
    }
}

// Acceptance: rekey can add encryption to a plaintext source and remove it
// from an encrypted source; the source is never mutated in place.
#[test]
fn rekey_adds_and_removes_encryption() {
    let dir = tempfile::tempdir().expect("tempdir");
    let plain = dir.path().join("plain.db");
    let encrypted = dir.path().join("encrypted.db");
    let decrypted = dir.path().join("decrypted.db");

    {
        let store = open_plain(&plain);
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("secret").expect("set_password");
    }

    let outcome = DbKeyStore::rekey(&plain, None, &encrypted, Some(&enc_opts(HEXKEY_256)))
        .expect("add encryption");
    assert_eq!(outcome.copied, 1);
    assert_eq!(
        password_of(&open_encrypted(&encrypted, HEXKEY_256), "svc", "user"),
        "secret"
    );

    let outcome = DbKeyStore::rekey(&encrypted, Some(&enc_opts(HEXKEY_256)), &decrypted, None)
        .expect("remove encryption");
    assert_eq!(outcome.copied, 1);
    assert_eq!(
        password_of(&open_plain(&decrypted), "svc", "user"),
        "secret"
    );
}

// Acceptance 5 (partial): rekey refuses to overwrite an existing destination.
#[test]
fn rekey_refuses_existing_destination() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");

    for path in [&src, &dst] {
        let store = open_plain(path);
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("pw").expect("set_password");
    }

    let err = DbKeyStore::rekey(&src, None, &dst, Some(&enc_opts(HEXKEY_256)))
        .expect_err("must refuse existing destination");
    assert!(
        matches!(err, RekeyError::DestinationExists(_)),
        "unexpected error: {err:?}"
    );
    // destination not touched
    let store = open_plain(&dst);
    assert_eq!(password_of(&store, "svc", "user"), "pw");
}

// Acceptance 5: a symlink at the destination (even dangling) is rejected, and
// the symlink target is not created or written.
#[cfg(unix)]
#[test]
fn rekey_refuses_symlink_destination() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    {
        let store = open_plain(&src);
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("pw").expect("set_password");
    }

    // dangling symlink
    let dst = dir.path().join("dst.db");
    let target = dir.path().join("elsewhere.db");
    std::os::unix::fs::symlink(&target, &dst).expect("symlink");
    let err = DbKeyStore::rekey(&src, None, &dst, Some(&enc_opts(HEXKEY_256)))
        .expect_err("must refuse symlink destination");
    assert!(
        matches!(err, RekeyError::DestinationExists(_)),
        "unexpected error: {err:?}"
    );
    assert!(
        !target.exists(),
        "symlink target must not be created through the symlink"
    );

    // symlink with an existing target
    std::fs::write(&target, b"do not clobber").expect("write target");
    let err = DbKeyStore::rekey(&src, None, &dst, Some(&enc_opts(HEXKEY_256)))
        .expect_err("must refuse symlink destination");
    assert!(matches!(err, RekeyError::DestinationExists(_)));
    assert_eq!(
        std::fs::read(&target).expect("read target"),
        b"do not clobber",
        "symlink target must be untouched"
    );
}

// Acceptance 4: wrong source DEK returns a typed error and never panics.
#[test]
fn wrong_source_key_returns_error_not_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");
    {
        let store = open_encrypted(&src, HEXKEY_256);
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("pw").expect("set_password");
    }

    let result = std::panic::catch_unwind(|| {
        DbKeyStore::rekey(
            &src,
            Some(&enc_opts(HEXKEY_256_WRONG)),
            &dst,
            Some(&enc_opts(HEXKEY_256_B)),
        )
    });
    let err = result
        .expect("rekey with wrong source key must not panic")
        .expect_err("rekey with wrong source key must fail");
    assert!(
        matches!(err, RekeyError::WrongSourceKey),
        "unexpected error: {err:?}"
    );
    assert!(!dst.exists(), "failed rekey must clean up the destination");

    // source unchanged and still readable under the right key
    let store = open_encrypted(&src, HEXKEY_256);
    assert_eq!(password_of(&store, "svc", "user"), "pw");
}

// Acceptance 4: opening an encrypted source with no key at all is also a
// typed error (indistinguishable from a non-database, so CorruptSource or
// WrongSourceKey are both acceptable) and never panics.
#[test]
fn missing_source_key_returns_error_not_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");
    {
        let store = open_encrypted(&src, HEXKEY_256);
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("pw").expect("set_password");
    }

    let result = std::panic::catch_unwind(|| DbKeyStore::rekey(&src, None, &dst, None));
    let err = result
        .expect("rekey without source key must not panic")
        .expect_err("rekey without source key must fail");
    assert!(
        matches!(
            err,
            RekeyError::CorruptSource(_) | RekeyError::WrongSourceKey | RekeyError::Database(_)
        ),
        "unexpected error: {err:?}"
    );
    assert!(!dst.exists(), "failed rekey must clean up the destination");
}

// A missing source is a typed error.
#[test]
fn missing_source_returns_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = DbKeyStore::rekey(
        dir.path().join("nope.db"),
        None,
        dir.path().join("dst.db"),
        None,
    )
    .expect_err("must fail for missing source");
    assert!(
        matches!(err, RekeyError::SourceNotFound(_)),
        "unexpected error: {err:?}"
    );
}

// Acceptance 3: transactions still sitting in the source WAL (source db held
// open, never checkpointed) are copied and verified.
#[test]
fn uncheckpointed_source_wal_is_copied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");

    // Keep the store open so nothing forces a checkpoint, then copy the
    // database and its live WAL to a new location: the copy has an
    // uncheckpointed WAL by construction.
    let wal = src.with_file_name("src.db-wal");
    {
        let store = open_plain(&src);
        for i in 0..10 {
            let entry = store
                .build("wal-svc", &format!("user-{i}"), None)
                .expect("build");
            entry.set_password(&format!("pw-{i}")).expect("set");
        }
        assert!(
            wal.metadata().map(|m| m.len() > 0).unwrap_or(false),
            "test setup: source WAL should contain uncheckpointed frames"
        );
        let frozen = dir.path().join("frozen.db");
        std::fs::copy(&src, &frozen).expect("copy db");
        std::fs::copy(&wal, frozen.with_file_name("frozen.db-wal")).expect("copy wal");

        let outcome =
            DbKeyStore::rekey(&frozen, None, &dst, Some(&enc_opts(HEXKEY_256))).expect("rekey");
        assert_eq!(outcome.copied, 10, "all WAL-resident records copied");
    }

    let store = open_encrypted(&dst, HEXKEY_256);
    for i in 0..10 {
        assert_eq!(
            password_of(&store, "wal-svc", &format!("user-{i}")),
            format!("pw-{i}")
        );
    }
}

// Ambiguous keystores (no unique (service,user) index) round-trip unchanged.
#[test]
fn ambiguous_source_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");

    {
        let config = DbKeyStoreConfig {
            path: src.clone(),
            allow_ambiguity: true,
            ..Default::default()
        };
        let store = DbKeyStore::new(config).expect("store");
        let uuid1 = "018f0000-0000-7000-8000-000000000001";
        let uuid2 = "018f0000-0000-7000-8000-000000000002";
        for (uuid, pw) in [(uuid1, "first"), (uuid2, "second")] {
            let entry = store
                .build("demo", "alice", Some(&HashMap::from([("uuid", uuid)])))
                .expect("build");
            entry.set_password(pw).expect("set");
        }
    }

    let outcome = DbKeyStore::rekey(&src, None, &dst, None).expect("rekey");
    assert_eq!(outcome.copied, 2);

    let config = DbKeyStoreConfig {
        path: dst.clone(),
        allow_ambiguity: true,
        ..Default::default()
    };
    let store = DbKeyStore::new(config).expect("dest store");
    let results = store
        .search(&HashMap::from([("service", "demo"), ("user", "alice")]))
        .expect("search");
    assert_eq!(results.len(), 2, "both ambiguous entries copied");
}

// Acceptance 7: an interrupted/failed rekey leaves the source usable and
// unchanged and removes the partial destination. The failure is triggered
// mid-copy by an invalid (oversized) secret planted in the source.
#[test]
fn interrupted_rekey_leaves_source_intact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");

    {
        let store = open_plain(&src);
        for (user, pw) in [("alice", "pw-a"), ("bob", "pw-b")] {
            let entry = store.build("svc", user, None).expect("build");
            entry.set_password(pw).expect("set");
        }
    }
    // plant an invalid row directly (bypassing the API's length validation)
    {
        let db = block_on(turso::Builder::new_local(src.to_str().unwrap()).build()).expect("db");
        let conn = db.connect().expect("conn");
        let oversized = vec![0u8; 100_000];
        block_on(conn.execute(
            "INSERT INTO credentials (service, user, uuid, secret) \
             VALUES ('svc', 'mallory', '018f0000-0000-7000-8000-0000000000ff', ?1)",
            (turso::Value::Blob(oversized),),
        ))
        .expect("insert oversized");
    }

    let err = DbKeyStore::rekey(&src, None, &dst, Some(&enc_opts(HEXKEY_256)))
        .expect_err("oversized source secret must fail rekey");
    assert!(
        matches!(err, RekeyError::CorruptSource(_)),
        "unexpected error: {err:?}"
    );
    assert!(!dst.exists(), "partial destination must be removed");
    assert_no_sidecars(&dst);

    // source remains usable and unchanged
    let store = open_plain(&src);
    assert_eq!(password_of(&store, "svc", "alice"), "pw-a");
    assert_eq!(password_of(&store, "svc", "bob"), "pw-b");
}

// Acceptance 10: success means a cleanly closed, durable candidate: the
// destination reopens read-consistent with no sidecar files present.
#[test]
fn success_returns_closed_durable_candidate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");
    {
        let store = open_plain(&src);
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("pw").expect("set");
    }
    DbKeyStore::rekey(&src, None, &dst, Some(&enc_opts(HEXKEY_256))).expect("rekey");
    assert_no_sidecars(&dst);
    #[cfg(unix)]
    assert_mode_0600(&dst);
    // reopening is enough to prove committed data is in the main db file, not
    // stranded in a WAL (the WAL was removed above)
    let store = open_encrypted(&dst, HEXKEY_256);
    assert_eq!(password_of(&store, "svc", "user"), "pw");
}

// Descriptor-relative rekey: dir-fd + name API works and survives the parent
// directory being renamed mid-operation setup (the descriptor stays
// authoritative after the path changes).
#[cfg(target_os = "linux")]
#[test]
fn rekey_at_descriptor_relative() {
    use std::os::fd::OwnedFd;

    let dir = tempfile::tempdir().expect("tempdir");
    let src_dir_path = dir.path().join("srcdir");
    let dst_dir_path = dir.path().join("dstdir");
    std::fs::create_dir(&src_dir_path).expect("mkdir src");
    std::fs::create_dir(&dst_dir_path).expect("mkdir dst");

    let src = src_dir_path.join("src.db");
    {
        let store = open_encrypted(&src, HEXKEY_256);
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("pw").expect("set");
    }

    let src_dir: OwnedFd = std::fs::File::open(&src_dir_path)
        .expect("open src dir")
        .into();
    let dst_dir: OwnedFd = std::fs::File::open(&dst_dir_path)
        .expect("open dst dir")
        .into();

    // rename the destination directory after pinning it: the operation must
    // still write into the pinned directory (substitution resistance)
    let moved_dst_dir = dir.path().join("dstdir-moved");
    std::fs::rename(&dst_dir_path, &moved_dst_dir).expect("rename dst dir");

    let (outcome, dest_fd) = db_keystore::rekey_at(
        &src_dir,
        "src.db",
        Some(&enc_opts(HEXKEY_256)),
        &dst_dir,
        "dst.db",
        Some(&enc_opts(HEXKEY_256_B)),
    )
    .expect("rekey_at");
    assert_eq!(outcome.copied, 1);

    // the destination landed in the pinned (renamed) directory
    let dst = moved_dst_dir.join("dst.db");
    assert!(dst.is_file(), "destination created in pinned directory");

    // the returned fd is the created destination file itself (custody
    // extends past the call: same dev/ino as the directory entry)
    {
        use std::os::unix::fs::MetadataExt;
        let fd_meta = std::fs::File::from(dest_fd).metadata().expect("fd meta");
        let entry_meta = dst.metadata().expect("entry meta");
        assert_eq!(
            (fd_meta.dev(), fd_meta.ino()),
            (entry_meta.dev(), entry_meta.ino()),
            "returned fd must refer to the created destination inode"
        );
    }
    assert_mode_0600(&dst);
    assert_no_sidecars(&dst);
    let store = open_encrypted(&dst, HEXKEY_256_B);
    assert_eq!(password_of(&store, "svc", "user"), "pw");
}

// rekey_at rejects multi-component names.
#[cfg(target_os = "linux")]
#[test]
fn rekey_at_rejects_path_components() {
    use std::os::fd::OwnedFd;

    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    {
        let store = open_plain(&src);
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("pw").expect("set");
    }
    let dir_fd: OwnedFd = std::fs::File::open(dir.path()).expect("open dir").into();
    let err = db_keystore::rekey_at(&dir_fd, "src.db", None, &dir_fd, "sub/dst.db", None)
        .expect_err("must reject name with path separator");
    assert!(
        matches!(err, RekeyError::UnsafeDestination(_)),
        "unexpected error: {err:?}"
    );
}

// Regression: rows that a normalizing copy would rewrite (uppercase uuid,
// empty-string comment, TEXT-storage-class secret) must be copied byte- and
// storage-class-exact and verify successfully.
#[test]
fn preserves_unusual_rows_byte_exact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");
    {
        // schema comes from a normal store; rows are planted raw
        let _ = open_plain(&src);
    }
    {
        let db = block_on(turso::Builder::new_local(src.to_str().unwrap()).build()).expect("db");
        let conn = db.connect().expect("conn");
        // uppercase uuid + empty-string comment + TEXT-class secret
        block_on(conn.execute(
            "INSERT INTO credentials (service, user, uuid, secret, comment) \
             VALUES ('svc', 'alice', '018F0000-0000-7000-8000-00000000000A', 'text-secret', '')",
            (),
        ))
        .expect("insert raw row");
        // BLOB-class comment (valid utf8)
        block_on(conn.execute(
            "INSERT INTO credentials (service, user, uuid, secret, comment) \
             VALUES ('svc', 'bob', '018f0000-0000-7000-8000-00000000000b', X'01FF', X'6E6F7465')",
            (),
        ))
        .expect("insert blob-comment row");
    }

    let outcome =
        DbKeyStore::rekey(&src, None, &dst, None).expect("rekey must preserve unusual rows");
    assert_eq!(outcome.copied, 2);

    // destination rows are identical to the source rows, including storage class
    let dump = |path: &Path| -> Vec<(String, String, String, String, String)> {
        let db = block_on(turso::Builder::new_local(path.to_str().unwrap()).build()).expect("db");
        let conn = db.connect().expect("conn");
        let mut rows = block_on(conn.query(
            "SELECT user, uuid, typeof(secret), hex(secret), coalesce(comment, '<null>') \
             FROM credentials ORDER BY user",
            (),
        ))
        .expect("query");
        let mut out = Vec::new();
        while let Some(row) = block_on(rows.next()).expect("next") {
            let field = |i: usize| match row.get_value(i).expect("value") {
                turso::Value::Text(t) => t,
                other => format!("{other:?}"),
            };
            out.push((field(0), field(1), field(2), field(3), field(4)));
        }
        out
    };
    let src_rows = dump(&src);
    let dst_rows = dump(&dst);
    assert_eq!(src_rows, dst_rows, "rows must round-trip exactly");
    assert_eq!(src_rows[0].1, "018F0000-0000-7000-8000-00000000000A");
    assert_eq!(src_rows[0].2, "text", "TEXT secret class preserved");
    assert_eq!(src_rows[0].4, "", "empty comment preserved (not NULL)");
}

// Regression: a pre-existing sidecar file at the destination is rejected and
// must NOT be deleted by the failure cleanup.
#[test]
fn preexisting_sidecar_is_rejected_not_deleted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");
    {
        let store = open_plain(&src);
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("pw").expect("set");
    }
    let stale_wal = dir.path().join("dst.db-wal");
    std::fs::write(&stale_wal, b"stale wal contents").expect("write stale wal");

    let err = DbKeyStore::rekey(&src, None, &dst, None)
        .expect_err("pre-existing sidecar must be rejected");
    assert!(
        matches!(err, RekeyError::DestinationExists(_)),
        "unexpected error: {err:?}"
    );
    assert_eq!(
        std::fs::read(&stale_wal).expect("stale wal must survive"),
        b"stale wal contents",
        "cleanup must not delete files it did not create"
    );
    assert!(!dst.exists(), "created main file must be cleaned up");
}

// Regression: a source with an unsupported schema_version is rejected instead
// of silently restamping the destination with the current version.
#[test]
fn unsupported_schema_version_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");
    {
        let store = open_plain(&src);
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("pw").expect("set");
    }
    {
        let db = block_on(turso::Builder::new_local(src.to_str().unwrap()).build()).expect("db");
        let conn = db.connect().expect("conn");
        block_on(conn.execute(
            "UPDATE keystore_meta SET value = '999' WHERE key = 'schema_version'",
            (),
        ))
        .expect("bump version");
    }
    let err = DbKeyStore::rekey(&src, None, &dst, None).expect_err("must reject future schema");
    assert!(
        matches!(err, RekeyError::CorruptSource(_)),
        "unexpected error: {err:?}"
    );
    assert!(!dst.exists(), "destination cleaned up");
}

// Standalone verification (B1): a faithfully rekeyed candidate verifies with
// the correct count; corrupting one destination secret afterwards is
// detected; a wrong destination key is a typed WrongDestinationKey (reachable
// now that verification re-opens an existing destination); a missing
// destination is DestinationNotFound; and verifying a cleanly-closed
// candidate leaves it cleanly closed (no sidecar files remain).
#[test]
fn verify_reverifies_candidate_and_detects_divergence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");
    {
        let store = open_plain(&src);
        for (user, pw) in [("alice", "pw-a"), ("bob", "pw-b")] {
            let entry = store.build("svc", user, None).expect("build");
            entry.set_password(pw).expect("set");
        }
    }
    DbKeyStore::rekey(&src, None, &dst, Some(&enc_opts(HEXKEY_256))).expect("rekey");

    // the candidate re-verifies after rekey has returned
    let verified = DbKeyStore::verify(&src, None, &dst, Some(&enc_opts(HEXKEY_256)))
        .expect("verify rekeyed candidate");
    assert_eq!(verified, 2, "all records verified");
    // verification must leave the cleanly-closed candidate cleanly closed
    assert_no_sidecars(&dst);

    // verification is repeatable (sidecar hygiene left nothing behind that
    // would change a second run)
    let verified =
        DbKeyStore::verify(&src, None, &dst, Some(&enc_opts(HEXKEY_256))).expect("verify again");
    assert_eq!(verified, 2);

    // wrong destination key: typed error, no panic
    let err = DbKeyStore::verify(&src, None, &dst, Some(&enc_opts(HEXKEY_256_WRONG)))
        .expect_err("wrong destination key must fail");
    assert!(
        matches!(err, RekeyError::WrongDestinationKey),
        "unexpected error: {err:?}"
    );

    // corrupt one destination secret without changing the row count
    {
        let db = block_on(
            turso::Builder::new_local(dst.to_str().unwrap())
                .experimental_encryption(true)
                .with_encryption(turso::EncryptionOpts {
                    cipher: "aes256gcm".to_string(),
                    hexkey: HEXKEY_256.to_string(),
                })
                .build(),
        )
        .expect("open dst raw");
        let conn = db.connect().expect("conn");
        let changed = block_on(conn.execute(
            "UPDATE credentials SET secret = X'DEADBEEF' WHERE user = 'bob'",
            (),
        ))
        .expect("corrupt");
        assert_eq!(changed, 1);
    }
    let err = DbKeyStore::verify(&src, None, &dst, Some(&enc_opts(HEXKEY_256)))
        .expect_err("must detect corrupted secret");
    assert!(
        matches!(err, RekeyError::VerificationMismatch(_)),
        "unexpected error: {err:?}"
    );

    // missing destination: typed error, nothing created
    let missing = dir.path().join("nope.db");
    let err =
        DbKeyStore::verify(&src, None, &missing, None).expect_err("missing destination must fail");
    assert!(
        matches!(err, RekeyError::DestinationNotFound(_)),
        "unexpected error: {err:?}"
    );
    assert!(!missing.exists(), "verify must not create the destination");
}

// verify() must not disturb a source whose credentials still live in an
// uncheckpointed WAL: the pre-existing WAL is read, never removed.
#[test]
fn verify_leaves_preexisting_source_wal_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");
    let wal = src.with_file_name("src.db-wal");
    {
        let store = open_plain(&src);
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("pw").expect("set");
    }
    assert!(
        wal.metadata().map(|m| m.len() > 0).unwrap_or(false),
        "test setup: source WAL should contain uncheckpointed frames"
    );
    DbKeyStore::rekey(&src, None, &dst, None).expect("rekey");

    let verified = DbKeyStore::verify(&src, None, &dst, None).expect("verify");
    assert_eq!(verified, 1);
    assert!(
        wal.metadata().map(|m| m.len() > 0).unwrap_or(false),
        "pre-existing source WAL must survive verification untouched"
    );
}

// Descriptor-relative verification (B1, Linux): verify_at re-verifies a
// candidate produced by rekey_at inside pinned directories, and detects
// divergence the same way.
#[cfg(target_os = "linux")]
#[test]
fn verify_at_descriptor_relative() {
    use std::os::fd::OwnedFd;

    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    {
        let store = open_plain(&src);
        for (user, pw) in [("alice", "pw-a"), ("bob", "pw-b")] {
            let entry = store.build("svc", user, None).expect("build");
            entry.set_password(pw).expect("set");
        }
    }
    let dir_fd: OwnedFd = std::fs::File::open(dir.path()).expect("open dir").into();

    let (outcome, _dest_fd) = db_keystore::rekey_at(
        &dir_fd,
        "src.db",
        None,
        &dir_fd,
        "dst.db",
        Some(&enc_opts(HEXKEY_256)),
    )
    .expect("rekey_at");
    assert_eq!(outcome.copied, 2);

    let verified = db_keystore::verify_at(
        &dir_fd,
        "src.db",
        None,
        &dir_fd,
        "dst.db",
        Some(&enc_opts(HEXKEY_256)),
    )
    .expect("verify_at");
    assert_eq!(verified, 2);
    // the candidate stays cleanly closed
    assert_no_sidecars(&dir.path().join("dst.db"));

    // a missing name is typed
    let err = db_keystore::verify_at(&dir_fd, "src.db", None, &dir_fd, "nope.db", None)
        .expect_err("missing destination must fail");
    assert!(
        matches!(err, RekeyError::DestinationNotFound(_)),
        "unexpected error: {err:?}"
    );

    // divergence is detected: remove a destination record via a raw handle
    {
        let dst = dir.path().join("dst.db");
        let db = block_on(
            turso::Builder::new_local(dst.to_str().unwrap())
                .experimental_encryption(true)
                .with_encryption(turso::EncryptionOpts {
                    cipher: "aes256gcm".to_string(),
                    hexkey: HEXKEY_256.to_string(),
                })
                .build(),
        )
        .expect("open dst raw");
        let conn = db.connect().expect("conn");
        block_on(conn.execute("DELETE FROM credentials WHERE user = 'bob'", ())).expect("delete");
    }
    let err = db_keystore::verify_at(
        &dir_fd,
        "src.db",
        None,
        &dir_fd,
        "dst.db",
        Some(&enc_opts(HEXKEY_256)),
    )
    .expect_err("must detect missing record");
    assert!(
        matches!(err, RekeyError::VerificationMismatch(_)),
        "unexpected error: {err:?}"
    );
}

// Missing destination parent directories are created (as in 0.4.x).
#[test]
fn dest_parent_directory_is_created() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("new").join("nested").join("dst.db");
    {
        let store = open_plain(&src);
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("pw").expect("set");
    }
    let outcome = DbKeyStore::rekey(&src, None, &dst, None).expect("rekey with new parent dirs");
    assert_eq!(outcome.copied, 1);
    assert_eq!(password_of(&open_plain(&dst), "svc", "user"), "pw");
}
