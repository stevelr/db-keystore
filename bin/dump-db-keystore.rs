//! Dump all keys in sqlite keystore to stdout.
//!
//! Syntax: dump [PATH] key=val ...
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut modifiers = HashMap::new();
    let mut path = None;
    for arg in args[1..].iter() {
        if let Some((key, val)) = arg.split_once('=') {
            if key == "path" {
                path = Some(val);
            }
            modifiers.insert(key, val);
        } else if path.is_none() {
            path = Some(arg);
            modifiers.insert("path", arg);
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
    let store = DbKeyStore::new_with_modifiers(&modifiers)?;
    let entries: Vec<Entry> = store.search(&HashMap::new())?;
    println!(
        "DbKeyStore {}. Listing {} keys:",
        store.path(),
        entries.len()
    );
    for entry in entries.iter() {
        let (service, user) = entry.get_specifiers().unwrap();
        let password = entry.get_password().unwrap_or_default();
        println!("{service}\t{user}\t{password}");
    }
    Ok(())
}
