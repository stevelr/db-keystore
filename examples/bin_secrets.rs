//! DbKeyStore example using text and binary secrets
//!
//! This example also shows use of Zeroizing to prevent secrets from leaking into heap memory.
//!
use db_keystore::{DbKeyStore, DbKeyStoreConfig};
use keyring_core::{Error, Result, api::CredentialStoreApi};
use std::collections::HashMap;
use zeroize::Zeroizing;

const SERVICE: &str = "bin_example";

fn main() -> Result<()> {
    let config = DbKeyStoreConfig::default();
    let store = DbKeyStore::new(config)?;
    println!("using store at {}", store.path());

    // `set_password` can be used to set secrets that are valid utf8 strings
    let entry = store.build(SERVICE, "textUser", None)?;
    let password = Zeroizing::new("dromomeryx".to_string());
    entry.set_password(password.as_str())?;

    // `set_secret` can set secrets that are any byte sequence
    let binary_entry = store.build(SERVICE, "binUser", None)?;
    let secret = Zeroizing::new(vec![0x00, 0xff, 0x80, 0x81, 0x82]);
    binary_entry.set_secret(secret.as_slice())?;

    // iterate through all all keys for service
    let results = store.search(&HashMap::from([("service", SERVICE)]))?;
    for entry in results.iter() {
        let (service, user) = entry.get_specifiers().unwrap();

        // `get_secret` can retrieve either text or binary secret
        let _secret = Zeroizing::new(entry.get_secret().unwrap());

        // `get_password` returns Ok for strings, and BadEncoding(Vec<u8>) for binary secrets
        match entry.get_password() {
            Ok(p) => {
                let p = Zeroizing::new(p);
                println!("{service}:{user} has password of length {}", p.len());
            }
            // get_password returns BadEncoding if secret is not text
            Err(Error::BadEncoding(buf)) => {
                let buf = Zeroizing::new(buf);
                println!("{service}:{user} has bin password of {} bytes", buf.len())
            }
            Err(e) => {
                eprintln!("error: {e:?} at entry for {service}:{user}")
            }
        }

        // clean up credentials after example run
        entry.delete_credential()?;
    }
    Ok(())
}
