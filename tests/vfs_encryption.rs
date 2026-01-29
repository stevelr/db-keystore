use std::collections::HashMap;

use db_keystore::{DbKeyStore, DbKeyStoreConfig, EncryptionOpts};
use keyring_core::api::CredentialStoreApi;
use zeroize::Zeroizing;

const HEXKEY_256: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

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
