use std::collections::HashMap;

use db_keystore::{DbKeyStore, DbKeyStoreConfig, EncryptionOpts};
use keyring_core::api::CredentialStoreApi;
use zeroize::Zeroizing;

const HEXKEY_256: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
// distinct N+1 key for rotation tests
const HEXKEY_256_B: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

#[test]
fn encryption_round_trip_requires_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("encrypted.db");
    let encryption_opts = Some(EncryptionOpts::new("aes256gcm", HEXKEY_256));

    {
        let config = DbKeyStoreConfig {
            path: path.clone(),
            encryption_opts: encryption_opts.clone(),
            ..Default::default()
        };
        let store = DbKeyStore::new(config).expect("create encrypted store");
        let entry = store
            .build("enc-service", "enc-user", None)
            .expect("build entry");
        let password = Zeroizing::new("dromomeryx".to_string());
        entry.set_password(password.as_str()).expect("set_password");
    }

    {
        let config = DbKeyStoreConfig {
            path: path.clone(),
            encryption_opts: encryption_opts.clone(),
            ..Default::default()
        };
        let store = DbKeyStore::new(config).expect("reopen encrypted store");
        let entry = store
            .build("enc-service", "enc-user", None)
            .expect("build entry");
        let value = Zeroizing::new(entry.get_password().expect("get_password"));
        assert_eq!(value.as_str(), "dromomeryx");
    }

    let config = DbKeyStoreConfig {
        path,
        ..Default::default()
    };
    let result = std::panic::catch_unwind(|| DbKeyStore::new(config));
    assert!(
        matches!(result, Ok(Err(_)) | Err(_)),
        "opening encrypted db without keys should fail"
    );
}

#[test]
fn vfs_memory_is_accepted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vfs-memory.db");
    let path_str = path.to_str().expect("path str");
    let modifiers = HashMap::from([("path", path_str), ("vfs", "memory")]);
    let store = DbKeyStore::new_with_modifiers(&modifiers).expect("vfs memory store");
    let entry = store
        .build("vfs-service", "vfs-user", None)
        .expect("build entry");
    let password = Zeroizing::new("dromomeryx".to_string());
    entry.set_password(password.as_str()).expect("set_password");
    let value = Zeroizing::new(entry.get_password().expect("get_password"));
    assert_eq!(value.as_str(), "dromomeryx");
}

fn open_encrypted(path: &std::path::Path, hexkey: &str) -> DbKeyStore {
    let config = DbKeyStoreConfig {
        path: path.to_path_buf(),
        encryption_opts: Some(EncryptionOpts::new("aes256gcm", hexkey)),
        ..Default::default()
    };
    // DbKeyStore::new returns Arc<DbKeyStore>; deref+clone for an owned value
    (*DbKeyStore::new(config).expect("open encrypted store")).clone()
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

// rotate-dek N -> N+1: every credential decrypts under the new key and matches
// the source; the source remains readable under the old key; the wrong
// destination key fails closed.
#[test]
fn rekey_rotates_dek_out_of_place() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("seq-n.db");
    let dst = dir.path().join("seq-n+1.db");

    // seed the source (sequence N) with several credentials, one with a comment
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

    // rotate to sequence N+1 under a new key
    let outcome = DbKeyStore::rekey(
        &src,
        Some(EncryptionOpts::new("aes256gcm", HEXKEY_256)),
        &dst,
        Some(EncryptionOpts::new("aes256gcm", HEXKEY_256_B)),
    )
    .expect("rekey");
    assert_eq!(outcome.copied, 3, "all three credentials copied");
    assert!(src.is_file(), "source left intact");
    assert!(dst.is_file(), "destination written");

    // destination decrypts under the NEW key and matches the source values
    {
        let store = open_encrypted(&dst, HEXKEY_256_B);
        assert_eq!(password_of(&store, "svc-a", "alice"), "pw-a");
        assert_eq!(password_of(&store, "svc-b", "bob"), "pw-b");
        assert_eq!(password_of(&store, "svc-c", "carol"), "pw-c");
        // comment-JSON attribute preserved across rekey
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

    // wrong destination key fails closed (no plaintext leak)
    {
        let config = DbKeyStoreConfig {
            path: dst.clone(),
            encryption_opts: Some(EncryptionOpts::new("aes256gcm", HEXKEY_256)),
            ..Default::default()
        };
        let result = std::panic::catch_unwind(|| DbKeyStore::new(config));
        assert!(
            matches!(result, Ok(Err(_)) | Err(_)),
            "opening rekeyed db with the old (wrong) key must fail"
        );
    }
}

// rekey can add encryption to a plaintext source and remove it from an
// encrypted source; the source is never mutated in place.
#[test]
fn rekey_adds_and_removes_encryption() {
    let dir = tempfile::tempdir().expect("tempdir");
    let plain = dir.path().join("plain.db");
    let encrypted = dir.path().join("encrypted.db");
    let decrypted = dir.path().join("decrypted.db");

    {
        let store = (*DbKeyStore::new(DbKeyStoreConfig {
            path: plain.clone(),
            ..Default::default()
        })
        .expect("plain store"))
        .clone();
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("secret").expect("set_password");
    }

    // add encryption (plaintext source, encrypted dest)
    let outcome = DbKeyStore::rekey(
        &plain,
        None,
        &encrypted,
        Some(EncryptionOpts::new("aes256gcm", HEXKEY_256)),
    )
    .expect("add encryption");
    assert_eq!(outcome.copied, 1);
    assert_eq!(
        password_of(&open_encrypted(&encrypted, HEXKEY_256), "svc", "user"),
        "secret"
    );

    // remove encryption (encrypted source, plaintext dest)
    let outcome = DbKeyStore::rekey(
        &encrypted,
        Some(EncryptionOpts::new("aes256gcm", HEXKEY_256)),
        &decrypted,
        None,
    )
    .expect("remove encryption");
    assert_eq!(outcome.copied, 1);
    let store = (*DbKeyStore::new(DbKeyStoreConfig {
        path: decrypted.clone(),
        ..Default::default()
    })
    .expect("plain dest"))
    .clone();
    assert_eq!(password_of(&store, "svc", "user"), "secret");
}

// rekey refuses to overwrite an existing destination.
#[test]
fn rekey_refuses_existing_destination() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.db");
    let dst = dir.path().join("dst.db");

    for path in [&src, &dst] {
        let store = (*DbKeyStore::new(DbKeyStoreConfig {
            path: path.clone(),
            ..Default::default()
        })
        .expect("store"))
        .clone();
        let entry = store.build("svc", "user", None).expect("build");
        entry.set_password("pw").expect("set_password");
    }

    let err = DbKeyStore::rekey(
        &src,
        None,
        &dst,
        Some(EncryptionOpts::new("aes256gcm", HEXKEY_256)),
    )
    .expect_err("must refuse existing destination");
    assert!(
        format!("{err:?}").contains("already exists"),
        "unexpected error: {err:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn vfs_io_uring_is_accepted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vfs-io-uring.db");
    let config = DbKeyStoreConfig {
        path,
        vfs: Some("io_uring".to_string()),
        ..Default::default()
    };
    let store = DbKeyStore::new(config).expect("vfs io_uring store");
    let entry = store
        .build("vfs-service", "vfs-user", None)
        .expect("build entry");
    let password = Zeroizing::new("dromomeryx".to_string());
    entry.set_password(password.as_str()).expect("set_password");
    let value = Zeroizing::new(entry.get_password().expect("get_password"));
    assert_eq!(value.as_str(), "dromomeryx");
}
