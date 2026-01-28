//! simple example for DbKeyStore
//!
use db_keystore::{DbKeyStore, DbKeyStoreConfig};
use keyring_core::{Result, api::CredentialStoreApi};
use std::collections::HashMap;

const SERVICE: &str = "basic_example";

fn main() -> Result<()> {
    // initialize keystore in default location
    let config = DbKeyStoreConfig::default();
    let store = DbKeyStore::new(&config)?;
    println!("using store at {}", store.path());

    // set password for user alice
    let entry = store.build(SERVICE, "alice", None)?;
    entry.set_password("dromomeryx")?;

    // set password for user bob
    let entry = store.build(SERVICE, "bob", None)?;
    entry.set_password("horse-staple")?;

    // retrieve a password
    let results = store.search(&HashMap::from([("service", SERVICE), ("user", "alice")]))?;
    let password = results.get(0).unwrap().get_password()?;
    assert_eq!(password, "dromomeryx");

    // cleanup: search for all users using regex and delete
    for entry in store.search(&HashMap::from([
        ("service", SERVICE),
        ("user", "alice|bob"),
    ]))? {
        entry.delete_credential()?;
    }
    Ok(())
}
