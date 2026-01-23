//! Example demonstrating encryption in DbKeyStore
//!
use db_keystore::{DbKeyStore, DbKeyStoreConfig, EncryptionOpts};
use keyring_core::api::CredentialStoreApi;
use std::{collections::HashMap, path::Path};

// See the project README (https://github.com/stevelr/db-keystore) for list of supported ciphers,
// and notes about key generation.
//
const CIPHER: &str = "aegis256";
// hexkey is 64 hex chars for 256 bit key. Create with (for example) `openssl rand -hex 32`
const HEXKEY: &str = "0000000011111111222222223333333344444444555555556666666677777777";

const SERVICE: &str = "enc_demo";

// From a rust app, create the keystore with DbKeyStore::new(DbKeyStoreConfig{...})
fn create_db_config(
    path: &Path,
    cipher: &str,
    hexkey: &str,
) -> Result<DbKeyStore, keyring_core::Error> {
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

// Entry path from `keyring`(https://crates.io/crates/keyring), (or its python library),
// using the name "sqlite" and string key=value modifiers
fn create_db_modifiers(
    path: &Path,
    cipher: &str,
    hexkey: &str,
) -> Result<DbKeyStore, keyring_core::Error> {
    let path = path.to_str().expect("path is utf8");
    let settings = HashMap::from([("path", path), ("cipher", cipher), ("hexkey", hexkey)]);
    DbKeyStore::new_with_modifiers(&settings)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let user = "alice";
    let password = "dromomeryx";
    let db_path = tempfile::tempdir()?.path().join("encrypted_keystore.db");

    // open or create keystore and store alice's password
    {
        let store = create_db_config(&db_path, CIPHER, HEXKEY)?;
        let entry = store.build(SERVICE, user, None)?;
        entry.set_password(password)?;
        println!("saved password");
    }
    // open the keystore, using modifier-style constructor, with same cipher & hexkey,
    // and retrieve the password
    {
        let store = create_db_modifiers(&db_path, CIPHER, HEXKEY)?;
        let results = store.search(&HashMap::from([("service", SERVICE), ("user", user)]))?;
        assert_eq!(results.len(), 1);

        let first = results.get(0).expect("found password");
        assert_eq!(first.get_password()?.as_str(), password);
        if &first.get_password()? == password {
            println!("passwords match!")
        }
    }
    Ok(())
}
