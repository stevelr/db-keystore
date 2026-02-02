//! Dump all keys in sqlite keystore to stdout.
//!
//! Syntax: dump-db-keystore [PATH] key=val ...
//!    PATH is path to existing database, defaults to ~/.local/state/keystore.db
//!    Additional args are modifiers. For encryption, use keys 'cipher' and 'hexkey'
//!   
//! SECURITY WARNING:
//!    This is a debugging tool that prints all secrets in the keystore. The existence
//!    of this program doesn't make the database less secure, but how you use use it might.
//!    For example, encryption keys passed on the command line may be logged in shell history.
//!
use db_keystore::DbKeyStore;
use keyring_core::{Entry, api::CredentialStoreApi};
use std::{collections::HashMap, path::PathBuf};
use zeroize::{Zeroize, Zeroizing};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().collect();
    let mut modifiers: HashMap<String, String> = HashMap::new();
    let mut path = None;
    for arg in args[1..].iter() {
        if let Some((key, val)) = arg.split_once('=') {
            if key == "path" {
                path = Some(val);
            }
            modifiers.insert(key.to_string(), val.to_string());
        } else if path.is_none() {
            path = Some(arg);
            modifiers.insert("path".to_string(), arg.to_string());
        } else {
            return Err(format!("Invalid arg '{}'. Expecting key=value", arg).into());
        }
    }
    // check for file existence, to avoid creating empty db
    match path {
        None => {
            let default_path = db_keystore::default_path()?;
            if !default_path.is_file() {
                return Err(
                    format!("No database at default path '{}'.", default_path.display()).into(),
                );
            }
        }
        Some(path) => {
            if !PathBuf::from(path).is_file() {
                return Err(format!("No database at '{path}'.").into());
            }
        }
    }
    let modifiers_ref: HashMap<&str, &str> = modifiers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let store = DbKeyStore::new_with_modifiers(&modifiers_ref)?;
    for value in modifiers.values_mut() {
        value.zeroize();
    }
    for arg in args.iter_mut() {
        arg.zeroize();
    }
    let entries: Vec<Entry> = store.search(&HashMap::new())?;
    println!(
        "DbKeyStore {}. Listing {} keys:",
        store.path(),
        entries.len()
    );
    for entry in entries.iter() {
        let (service, user) = entry.get_specifiers().unwrap();
        let password = Zeroizing::new(entry.get_password().unwrap_or_default());
        println!("{service}\t{user}\t{}", password.as_str());
    }
    Ok(())
}
