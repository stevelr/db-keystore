//! Demonstrates the panic when db is opened with the wrong key,
//! and how to catch it. The panic will be fixed in an upcoming version of db-keystore
//! after it's released in turso.
//!

use db_keystore::{DbKeyStore, DbKeyStoreConfig, EncryptionOpts};
use keyring_core::api::CredentialStoreApi;
use std::{collections::HashMap, panic, path::Path, sync::Arc};

// See project README for list of supported ciphers and notes on creating
// and securing keys.
//
// supported ciphers include "aegis2456", "aes256gcm", and others
const CIPHER: &str = "aegis256";
// hexkey is 64 hex chars for 256 bit key. Create with (for example) `openssl rand -hex 32`
const HEXKEY: &str = "0000000011111111222222223333333344444444555555556666666677777777";

fn create_db_config(
    path: &Path,
    cipher: &str,
    hexkey: &str,
) -> Result<Arc<DbKeyStore>, keyring_core::Error> {
    let encryption_opts = EncryptionOpts {
        cipher: cipher.to_string(),
        hexkey: hexkey.to_string(),
    };
    let config = DbKeyStoreConfig {
        path: path.to_owned(),
        encryption_opts: Some(encryption_opts),
        ..Default::default()
    };
    DbKeyStore::new(&config)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = "demo";
    let user = "alice";
    let password = "dromomeryx";
    let db_path = tempfile::tempdir()?.path().join("encrypted_wrongkey.db");

    // store password for alice
    {
        let store = create_db_config(&db_path, CIPHER, HEXKEY)?;
        let entry = store.build(service, user, None)?;
        entry.set_password(password)?;
    }
    {
        // trying to open db with wrong password panics in turso v0.4.3.
        // Fixed in PR 4670 https://github.com/tursodatabase/turso/pull/4670
        let store = match panic::catch_unwind(panic::AssertUnwindSafe(|| {
            create_db_config(&db_path, CIPHER, &HEXKEY.replace("000", "123"))
        })) {
            // opened with correct key
            Ok(Ok(store)) => {
                println!("opened ok");
                store
            }
            // Some other open error
            Ok(Err(e)) => {
                eprintln!("Open failed: {e:?}");
                std::process::exit(1);
            }
            // Wrong key
            Err(panic_payload) => {
                eprintln!("Panic caught opening encrypted db with wrong key.");
                std::mem::forget(panic_payload);
                std::process::exit(1);
            }
        };

        let results = store.search(&HashMap::from([("service", service), ("user", user)]))?;
        assert_eq!(results.len(), 1);
        let first = results.get(0).expect("found password");
        assert_eq!(first.get_password()?.as_str(), password);
        if &first.get_password()? == password {
            println!("passwords match!")
        }
    }

    Ok(())
}
