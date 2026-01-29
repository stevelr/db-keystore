//! CLI for db-keystore maintenance and inspection.
//!
//! Options
//!   --path
//!   --cipher
//!   --hexkey
//!
//! Subcommands:
//!
//!   list                   - list all credentials: service, user, uuid, comment (does not display secrets)
//!      --json              - output in json instead of tsv
//!      --ambiguous         - list ambiguous entries (where service,user are not unique)
//!      --service SVC       - limit listing to the service
//!      --user USER         - limit listing to the user
//!
//!   delete
//!      --uuid UUID         - delete the entry with the uuid
//!      -s SERVICE -u USER  - delete entry for this service/user
//!
//!   allow-ambiguous        - allow ambiguous entries (removes UNIQUE index)
//!
//!   rekey                  - add or remove encryption, or change encryption key
//!      -o/--output PATH    - path to new file
//!      --new-cipher        - new encryption cipher
//!      --new-hexkey        - new encryption key
//!
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand};
use db_keystore::{DbKeyStore, DbKeyStoreConfig, EncryptionOpts};
use keyring_core::{Entry, Error as KeyringError, api::CredentialStoreApi};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::exit;
use zeroize::{Zeroize, Zeroizing};

use futures::executor::block_on;
use turso::{Builder, Connection, Database, Value};

#[derive(Parser, Debug)]
#[command(name = "db-keystore", version, about = "Manage db-keystore databases")]
struct Cli {
    /// Path to keystore (defaults to $XDG_STATE_HOME/keystore.db or $HOME/.local/state/keystore.db)
    #[arg(long, global = true)]
    path: Option<PathBuf>,

    /// Encryption cipher
    #[arg(long, global = true)]
    cipher: Option<String>,

    /// Encryption key (hex)
    #[arg(long, global = true)]
    hexkey: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List credentials
    List(ListArgs),
    /// Delete a credential
    Delete(DeleteArgs),
    /// Remove unique index to allow ambiguous entries
    AllowAmbiguous,
    /// Rekey to a new database (and/or new cipher)
    Rekey(RekeyArgs),
}

#[derive(Args, Debug)]
struct ListArgs {
    /// Filter by service
    #[arg(short = 's', long)]
    service: Option<String>,
    /// Filter by user
    #[arg(short = 'u', long)]
    user: Option<String>,
    /// Show only ambiguous entries (same service/user)
    #[arg(long)]
    ambiguous: bool,
    /// Output JSON instead of TSV
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct DeleteArgs {
    /// Delete by UUID
    #[arg(long)]
    uuid: Option<String>,
    /// Delete by service
    #[arg(short = 's', long)]
    service: Option<String>,
    /// Delete by user
    #[arg(short = 'u', long)]
    user: Option<String>,
}

#[derive(Args, Debug)]
struct RekeyArgs {
    /// Output path for new database
    #[arg(short = 'o', long)]
    output: PathBuf,
    /// New encryption cipher
    #[arg(long = "new-cipher")]
    new_cipher: Option<String>,
    /// New encryption key (hex)
    #[arg(long = "new-hexkey")]
    new_hexkey: Option<String>,
}

#[derive(serde::Serialize, Clone)]
struct ListRow {
    service: String,
    user: String,
    uuid: String,
    comment: Option<String>,
}

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err:#}");
            2
        }
    };
    exit(code);
}

fn run() -> Result<i32> {
    let cli = Cli::parse();

    let cipher_opts = validate_cipher_and_key(cli.cipher, cli.hexkey)?;

    match cli.command {
        Command::List(args) => cmd_list(cli.path, cipher_opts, args),
        Command::Delete(args) => cmd_delete(cli.path, cipher_opts, args),
        Command::AllowAmbiguous => cmd_allow_ambiguous(cli.path, cipher_opts),
        Command::Rekey(args) => cmd_rekey(cli.path, cipher_opts, args),
    }
}

fn cmd_list(
    path: Option<PathBuf>,
    cipher_opts: Option<(String, Zeroizing<String>)>,
    args: ListArgs,
) -> Result<i32> {
    let resolved_path = resolve_path(path)?;
    ensure_db_exists(&resolved_path)?;

    let store = open_store(&resolved_path, &cipher_opts)?;
    let mut spec: HashMap<&str, &str> = HashMap::new();
    if let Some(service) = args.service.as_deref() {
        spec.insert("service", service);
    }
    if let Some(user) = args.user.as_deref() {
        spec.insert("user", user);
    }

    let entries = store.search(&spec)?;
    let mut rows = entries_to_rows(entries)?;
    rows.sort_by(|a, b| {
        (a.service.as_str(), a.user.as_str(), a.uuid.as_str()).cmp(&(
            b.service.as_str(),
            b.user.as_str(),
            b.uuid.as_str(),
        ))
    });

    if args.ambiguous {
        let ambiguous = filter_ambiguous(&rows);
        if ambiguous.is_empty() {
            eprintln!("No ambiguities");
            return Ok(0);
        }
        output_rows(&ambiguous, args.json)?;
        return Ok(0);
    }

    output_rows(&rows, args.json)?;
    Ok(0)
}

fn cmd_delete(
    path: Option<PathBuf>,
    cipher_opts: Option<(String, Zeroizing<String>)>,
    args: DeleteArgs,
) -> Result<i32> {
    let resolved_path = resolve_path(path)?;
    ensure_db_exists(&resolved_path)?;
    let store = open_store(&resolved_path, &cipher_opts)?;

    match (args.uuid, args.service, args.user) {
        (Some(uuid), None, None) => delete_by_uuid(&store, &uuid),
        (None, Some(service), Some(user)) => delete_by_service_user(&store, &service, &user),
        _ => bail!("delete requires either --uuid UUID or -s SERVICE -u USER (and no extra args)"),
    }
}

fn cmd_allow_ambiguous(
    path: Option<PathBuf>,
    cipher_opts: Option<(String, Zeroizing<String>)>,
) -> Result<i32> {
    let resolved_path = resolve_path(path)?;
    ensure_db_exists(&resolved_path)?;

    let conn = open_conn(&resolved_path, cipher_opts.as_ref())?;
    remove_unique_index_or_rebuild(&conn)?;
    Ok(0)
}

fn cmd_rekey(
    path: Option<PathBuf>,
    cipher_opts: Option<(String, Zeroizing<String>)>,
    args: RekeyArgs,
) -> Result<i32> {
    let resolved_path = resolve_path(path)?;
    ensure_db_exists(&resolved_path)?;

    ensure!(
        !args.output.exists(),
        "output path '{}' already exists",
        args.output.display()
    );

    let store = open_store(&resolved_path, &cipher_opts)?;
    let encrypted = store.is_encrypted();

    let new_cipher_opts = validate_cipher_and_key(args.new_cipher, args.new_hexkey)?;
    if !encrypted && new_cipher_opts.is_none() {
        bail!("database is not encrypted; --new-cipher and --new-hexkey are required");
    }

    let allow_ambiguity = detect_allow_ambiguity(&resolved_path, &cipher_opts)?;

    let encryption_opts = new_cipher_opts
        .as_ref()
        .map(|(cipher, hexkey)| EncryptionOpts::new(cipher.clone(), hexkey.as_str().to_string()));
    let config = DbKeyStoreConfig {
        path: args.output.clone(),
        allow_ambiguity,
        encryption_opts,
        ..Default::default()
    };
    let new_store = DbKeyStore::new(config).context("failed to create new keystore")?;

    let entries = store
        .search(&HashMap::new())
        .context("failed to read entries for rekey")?;
    for entry in entries {
        copy_entry(&entry, &new_store)?;
    }

    Ok(0)
}

fn validate_cipher_and_key(
    cipher: Option<String>,
    hexkey: Option<String>,
) -> Result<Option<(String, Zeroizing<String>)>> {
    match (cipher, hexkey) {
        (None, None) => Ok(None),
        (Some(cipher), Some(hexkey)) => {
            let cipher = cipher.to_ascii_lowercase();
            let expected_len = expected_hex_len(&cipher)
                .with_context(|| format!("unsupported cipher '{cipher}'"))?;
            ensure!(
                hexkey.len() == expected_len,
                "hexkey length must be {expected_len} for cipher '{cipher}'"
            );
            ensure!(
                hexkey.chars().all(|c| c.is_ascii_hexdigit()),
                "hexkey must be valid hex"
            );
            Ok(Some((cipher, Zeroizing::new(hexkey))))
        }
        _ => bail!("cipher and hexkey must be provided together"),
    }
}

fn expected_hex_len(cipher: &str) -> Option<usize> {
    match cipher {
        "aegis128l" | "aegis128x2" | "aegis128x4" | "aes128gcm" => Some(32),
        "aegis256" | "aegis256x2" | "aegis256x4" | "aes256gcm" => Some(64),
        _ => None,
    }
}

fn resolve_path(path: Option<PathBuf>) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path),
        None => db_keystore::default_path().context("failed to determine default keystore path"),
    }
}

fn ensure_db_exists(path: &Path) -> Result<()> {
    ensure!(path.is_file(), "no database at '{}'", path.display());
    Ok(())
}

fn open_store(
    path: &Path,
    cipher_opts: &Option<(String, Zeroizing<String>)>,
) -> Result<DbKeyStore> {
    let mut modifiers: HashMap<String, String> = HashMap::new();
    let path_str = path.to_str().context("path must be valid UTF-8")?;
    modifiers.insert("path".to_string(), path_str.to_string());
    if let Some((cipher, hexkey)) = cipher_opts.as_ref() {
        modifiers.insert("cipher".to_string(), cipher.clone());
        modifiers.insert("hexkey".to_string(), hexkey.as_str().to_string());
    }

    let modifiers_ref: HashMap<&str, &str> = modifiers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let store =
        DbKeyStore::new_with_modifiers(&modifiers_ref).context("failed to open keystore")?;

    for value in modifiers.values_mut() {
        value.zeroize();
    }

    Ok((*store).clone())
}

fn entries_to_rows(entries: Vec<Entry>) -> Result<Vec<ListRow>> {
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        let (service, user) = entry
            .get_specifiers()
            .context("entry missing service/user")?;
        let attrs = entry.get_attributes()?;
        let uuid = attrs.get("uuid").cloned().context("entry missing uuid")?;
        let comment = attrs.get("comment").cloned();
        rows.push(ListRow {
            service,
            user,
            uuid,
            comment,
        });
    }
    Ok(rows)
}

fn filter_ambiguous(rows: &[ListRow]) -> Vec<ListRow> {
    let mut counts: HashMap<(&str, &str), usize> = HashMap::new();
    for row in rows {
        *counts
            .entry((row.service.as_str(), row.user.as_str()))
            .or_insert(0) += 1;
    }
    rows.iter()
        .filter(|row| counts.get(&(row.service.as_str(), row.user.as_str())) > Some(&1))
        .cloned()
        .collect()
}

fn output_rows(rows: &[ListRow], json: bool) -> Result<()> {
    if json {
        let output = serde_json::to_string_pretty(rows)?;
        println!("{output}");
        return Ok(());
    }

    for row in rows {
        let comment = row.comment.as_deref().unwrap_or("");
        println!("{}\t{}\t{}\t{}", row.service, row.user, row.uuid, comment);
    }
    Ok(())
}

fn delete_by_uuid(store: &DbKeyStore, uuid: &str) -> Result<i32> {
    let normalized = normalize_uuid(uuid)?;
    let spec = HashMap::from([("uuid", normalized.as_str())]);
    let entries = store.search(&spec)?;
    if entries.is_empty() {
        println!("Not found");
        return Ok(1);
    }

    let entry = entries.into_iter().next().context("missing entry")?;
    match entry.delete_credential() {
        Ok(()) => {
            println!("Deleted");
            Ok(0)
        }
        Err(KeyringError::NoEntry) => {
            println!("Not found");
            Ok(1)
        }
        Err(KeyringError::Ambiguous(_)) => bail!("ambiguous: multiple entries match this uuid"),
        Err(err) => Err(err.into()),
    }
}

fn delete_by_service_user(store: &DbKeyStore, service: &str, user: &str) -> Result<i32> {
    let entry = store.build(service, user, None)?;
    match entry.delete_credential() {
        Ok(()) => {
            println!("Deleted");
            Ok(0)
        }
        Err(KeyringError::NoEntry) => {
            println!("Not Found");
            Ok(1)
        }
        Err(KeyringError::Ambiguous(_)) => {
            println!("Ambiguous");
            Ok(1)
        }
        Err(err) => Err(err.into()),
    }
}

fn normalize_uuid(value: &str) -> Result<String> {
    let uuid = uuid::Uuid::parse_str(value).context("invalid uuid format")?;
    Ok(uuid.to_string())
}

fn copy_entry(entry: &Entry, new_store: &DbKeyStore) -> Result<()> {
    let (service, user) = entry
        .get_specifiers()
        .context("entry missing service/user")?;
    let attrs = entry.get_attributes()?;
    let uuid = attrs.get("uuid").cloned().context("entry missing uuid")?;
    let comment = attrs.get("comment").cloned();

    let mut mods: HashMap<&str, &str> = HashMap::new();
    mods.insert("uuid", uuid.as_str());
    if let Some(comment) = comment.as_deref() {
        mods.insert("comment", comment);
    }

    let new_entry = new_store.build(service.as_str(), user.as_str(), Some(&mods))?;

    let secret = Zeroizing::new(entry.get_secret()?);
    new_entry.set_secret(secret.as_slice())?;
    Ok(())
}

fn detect_allow_ambiguity(
    path: &Path,
    cipher_opts: &Option<(String, Zeroizing<String>)>,
) -> Result<bool> {
    let conn = open_conn(path, cipher_opts.as_ref())?;
    let has_unique_index = find_unique_service_user_index(&conn)?.is_some();
    if has_unique_index {
        return Ok(false);
    }
    let has_table_unique = table_has_unique_service_user(&conn)?;
    Ok(!has_table_unique)
}

fn open_conn(path: &Path, cipher_opts: Option<&(String, Zeroizing<String>)>) -> Result<Connection> {
    let path_str = path.to_str().context("path must be valid UTF-8")?;
    let db = open_db(path_str, cipher_opts)?;
    Ok(db.connect()?)
}

fn open_db(path: &str, cipher_opts: Option<&(String, Zeroizing<String>)>) -> Result<Database> {
    let mut builder = Builder::new_local(path);
    if let Some((cipher, hexkey)) = cipher_opts {
        let turso_opts = turso::EncryptionOpts {
            cipher: cipher.clone(),
            hexkey: hexkey.as_str().to_string(),
        };
        builder = builder
            .experimental_encryption(true)
            .with_encryption(turso_opts);
    }
    block_on(builder.build()).context("failed to open database")
}

// Remove unique index: First try to drop it.
// If that doesn't work, fall back to rebuilding the table (copy rows, drop old table, rename)
fn remove_unique_index_or_rebuild(conn: &Connection) -> Result<()> {
    let index_name = find_unique_service_user_index(conn)?;
    if let Some(index_name) = index_name {
        let drop_sql = format!("DROP INDEX IF EXISTS {}", quote_ident(&index_name));
        match block_on(conn.execute(drop_sql.as_str(), ())) {
            Ok(_) => return Ok(()),
            Err(err) => {
                let message = err.to_string();
                if !message
                    .to_lowercase()
                    .contains("index associated with unique or primary key constraint")
                {
                    return Err(err).context("failed to drop unique index");
                }
            }
        }
    }
    if table_has_unique_service_user(conn)? {
        rebuild_credentials_without_unique(conn)?;
    }
    Ok(())
}

fn find_unique_service_user_index(conn: &Connection) -> Result<Option<String>> {
    let mut rows = block_on(conn.query(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'credentials' AND sql IS NOT NULL",
        (),
    ))
    .context("failed to query indexes")?;
    while let Some(row) = block_on(rows.next())? {
        let name = value_to_string(row.get_value(0)?, "index name")?;
        let sql = value_to_string(row.get_value(1)?, "sql")?;
        if is_unique_service_user_sql(sql.as_str()) {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

fn table_has_unique_service_user(conn: &Connection) -> Result<bool> {
    let mut rows = block_on(conn.query(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'credentials' AND sql IS NOT NULL",
        (),
    ))
    .context("failed to query table schema")?;
    if let Some(row) = block_on(rows.next())? {
        let sql = value_to_string(row.get_value(0)?, "sql")?;
        return Ok(is_unique_service_user_sql(sql.as_str()));
    }
    Ok(false)
}

fn is_unique_service_user_sql(sql: &str) -> bool {
    let normalized = normalize_sql(sql);
    normalized.contains("unique") && normalized.contains("(service,user)")
}

fn normalize_sql(sql: &str) -> String {
    sql.chars()
        .filter(|c| !c.is_whitespace() && *c != '"' && *c != '`')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn quote_ident(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

fn rebuild_credentials_without_unique(conn: &Connection) -> Result<()> {
    block_on(conn.execute("BEGIN IMMEDIATE", ())).context("failed to begin transaction")?;
    let result: Result<()> = (|| {
        block_on(conn.execute(
            "CREATE TABLE credentials_new (service TEXT NOT NULL, user TEXT NOT NULL, uuid TEXT NOT NULL, secret BLOB NOT NULL, comment TEXT)",
            (),
        ))
        .context("failed to create temporary table")?;
        block_on(conn.execute(
            "INSERT INTO credentials_new (service, user, uuid, secret, comment) SELECT service, user, uuid, secret, comment FROM credentials",
            (),
        ))
        .context("failed to copy credentials")?;
        block_on(conn.execute("DROP TABLE credentials", ())).context("failed to drop old table")?;
        block_on(conn.execute("ALTER TABLE credentials_new RENAME TO credentials", ()))
            .context("failed to rename table")?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            block_on(conn.execute("COMMIT", ())).context("failed to commit transaction")?;
            Ok(())
        }
        Err(err) => {
            // if rollback fails while handling error, don't raise. Log it and return primary error.
            if let Err(e2) = block_on(conn.execute("ROLLBACK", ())) {
                eprintln!(
                    "Failed to create tables: ({err:#}). While handling that error, attempted ROLLBACK and encountered {e2}"
                );
            }
            Err(err)
        }
    }
}
fn value_to_string(value: Value, field: &str) -> Result<String> {
    match value {
        Value::Text(text) => Ok(text),
        Value::Blob(blob) => {
            String::from_utf8(blob).with_context(|| format!("invalid utf8 for {field}"))
        }
        other @ Value::Null | other @ Value::Integer(_) | other @ Value::Real(_) => {
            bail!("unexpected value for {field}: {other:?}")
        }
    }
}
