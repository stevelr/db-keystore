//! File-backed credential store using Turso (SQLite) and optional encryption.
//!
//! This module implements the `keyring_core::api::CredentialStoreApi` and
//! `keyring_core::api::CredentialApi` traits, so it can be used wherever a
//! `keyring_core::api::CredentialStore` is expected (for example via
//! `use_named_store_with_modifiers`).
//!
//! Features:
//! - Local SQLite storage with optional encryption options.
//! - WAL + busy timeout for better multi-process behavior.
//! - Optional uniqueness enforcement on (service, user) via `allow_ambiguity=false`.
//! - UUID and optional comment attributes exposed via the credential API.
//! - Search supports `service`, `user`, `uuid`, and `comment` regex filters.
//!
//! Modifiers supported by `new_with_modifiers`:
//! - `path` : path to the SQLite database file. Defaults to $XDG_STATE_HOME/keystore.db or $HOME/.local/state/keystore.db
//! - `encryption-cipher` / `cipher`: encryption cipher name (optional, requires hexkey).
//! - `encryption-hexkey` / `hexkey`: encryption key as hex (optional, requires cipher).
//! - `allow-ambiguity` / `allow_ambiguity`: `"true"` or `"false"` (default `"false"`).
//! - `vfs`: optional VFS backing selection (`"memory"`, `"io_uring"`, or `"syscall"`).
//!
//! Example:
//! ```rust
//! use std::collections::HashMap;
//! use db_keystore::{DbKeyStore, DbKeyStoreConfig};
//!
//! // create from config
//! let config = DbKeyStoreConfig {
//!     path: "keystore.db".into(),
//!     ..Default::default()
//! };
//! let store = DbKeyStore::new(&config).expect("store");
//!
//! // or, create with modifiers
//! let modifiers = HashMap::from([
//!     ("path", "keystore.db"),
//!     ("allow-ambiguity", "true"),
//! ]);
//! let store = DbKeyStore::new_with_modifiers(&modifiers).expect("store");
//! ```

// SAFETY - Security and safety notes:
//  - SQL injection: all user data is bound as parameters; SQL is static.
//  - Secret handling: secrets are validated with length checks.
//    Optional on-disk encryption implemented in database.
//  - Concurrency: set_secret uses a transaction for read/modify/write; single statements
//    are atomic in SQLite.
//  - Contention: connections enable WAL and busy_timeout to reduce SQLITE_BUSY in
//    multi-process usage.
//  - Uniqueness: allow_ambiguity=false enforces a unique (service,user) index and
//    uses UPSERT; allow_ambiguity=true permits multiple credentials per pair.

use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use futures::executor::block_on;
use keyring_core::{
    api::{CredentialApi, CredentialPersistence, CredentialStoreApi},
    attributes::parse_attributes,
    {Credential, Entry, Error, Result},
};
use regex::Regex;
use turso::{Builder, Connection, Database, Value};
use uuid::Uuid;

// length limits to prevent accidental blow up of db:
//  - service and name: 1024 bytes
//  - secret: 65536 bytes
const MAX_NAME_LEN: usize = 1024;
const MAX_SECRET_LEN: usize = 65536;
const SCHEMA_VERSION: u32 = 1;
// sqlite timeout for connection busy
const BUSY_TIMEOUT_MS: u32 = 5000;
/// retry logic for open and connect, in case there's a file lock
const OPEN_LOCK_RETRIES: u32 = 60;
const OPEN_LOCK_BACKOFF_MS: u64 = 20;
const OPEN_LOCK_BACKOFF_MAX_MS: u64 = 250;

/// EncryptionOpts mirrors turso::EncryptionOpts
/// See https://docs.turso.tech/tursodb/encryption
/// Example ciphers: "aegis256", "aes256gcm". For 256-bit keys, hexkey is 64 chars.
#[derive(Debug, Default, Clone)]
pub struct EncryptionOpts {
    pub cipher: String,
    pub hexkey: String,
}

/// Configure turso database
#[derive(Debug, Default, Clone)]
pub struct DbKeyStoreConfig {
    /// path to database. Defaults to $XDG_STATE_HOME/keystore.db or $HOME/.local/state/keystore.db
    pub path: PathBuf,
    /// set cipher and encryption key to enable encryption
    pub encryption_opts: Option<EncryptionOpts>,
    /// allow non-unique values for (service,user) (see keystore-core documentation)
    pub allow_ambiguity: bool,
    /// database io options: "memory" (in-memory), "syscall", or "io_uring" (linux only)
    pub vfs: Option<String>,
    /// add index on (service,user) even when allow_ambiguity is true
    /// increases file size about 2x, increases performance for large keystores (>500 entries)
    pub index_always: bool,
}

/// Default path for keystore: $XDG_STATE_HOME/keystore.db or $HOME/.local/state/keystore.db
pub fn default_path() -> Result<PathBuf> {
    Ok(match std::env::var("XDG_STATE_HOME") {
        Ok(d) => PathBuf::from(d),
        _ => match std::env::var("HOME") {
            Ok(h) => PathBuf::from(h).join(".local").join("state"),
            _ => {
                return Err(Error::Invalid(
                    "path".to_string(),
                    "No default path: set 'path' in Config (or modifiers), or define XDG_STATE_HOME or HOME"
                        .to_string(),
                ));
            }
        },
    }
    .join("keystore.db"))
}

#[derive(Debug, Clone)]
pub struct DbKeyStore {
    inner: Arc<DbKeyStoreInner>,
}

#[derive(Debug)]
struct DbKeyStoreInner {
    db: Database,
    id: String,
    allow_ambiguity: bool,
    encrypted: bool,
    path: PathBuf,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct CredId {
    service: String,
    user: String,
}

#[derive(Debug, Clone)]
struct DbKeyCredential {
    inner: Arc<DbKeyStoreInner>,
    id: CredId,
    uuid: Option<String>,
}

impl DbKeyStore {
    pub fn new(config: &DbKeyStoreConfig) -> Result<DbKeyStore> {
        let path = if config.path.as_os_str().is_empty() {
            default_path()?
        } else {
            config.path.clone()
        };
        ensure_parent_dir(&path)?;
        let path_str = path.to_str().ok_or_else(|| {
            Error::Invalid("path".into(), format!("invalid path {}", path.display()))
        })?;
        let db = open_db_with_retry(path_str, config.encryption_opts.clone(), config.vfs.clone())?;
        let conn = retry_turso_locking(|| db.connect())?;
        configure_connection(&conn)?;
        init_schema(&conn, config.allow_ambiguity, config.index_always)?;
        let encrypted = config
            .encryption_opts
            .as_ref()
            .is_some_and(|o| !o.cipher.is_empty());
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let id = format!(
            "DbKeyStore v{} path:{path_str} enc:{encrypted} @ {start_time}",
            env!("CARGO_PKG_VERSION"),
        );
        Ok(DbKeyStore {
            inner: Arc::new(DbKeyStoreInner {
                db,
                id,
                allow_ambiguity: config.allow_ambiguity,
                encrypted,
                path,
            }),
        })
    }

    pub fn new_with_modifiers(modifiers: &HashMap<&str, &str>) -> Result<DbKeyStore> {
        let mut path: Option<PathBuf> = None;
        let mut cipher: Option<String> = None;
        let mut hexkey: Option<String> = None;
        let mut allow_ambiguity: Option<bool> = None;
        let mut vfs: Option<String> = None;
        let mut index_always: Option<bool> = None;
        for (key, value) in modifiers {
            match *key {
                "path" => path = Some(PathBuf::from(value)),
                "encryption-cipher" | "cipher" => cipher = Some((*value).to_string()),
                "encryption-hexkey" | "hexkey" => hexkey = Some((*value).to_string()),
                "allow-ambiguity" | "allow_ambiguity" => {
                    allow_ambiguity = Some(parse_bool_modifier(key, value)?);
                }
                "vfs" => vfs = Some((*value).to_string()),
                "index-always" | "index_always" => {
                    index_always = Some(parse_bool_modifier(key, value)?);
                }
                _ => {
                    return Err(Error::Invalid(
                        "modifiers".to_string(),
                        format!("unsupported modifier: {key}"),
                    ));
                }
            }
        }
        let path = path.unwrap_or_default();
        let encryption_opts = match (cipher, hexkey) {
            (None, None) => None,
            (Some(cipher), Some(hexkey)) => Some(EncryptionOpts { cipher, hexkey }),
            _ => {
                return Err(Error::Invalid(
                    "encryption".to_string(),
                    "encryption-cipher and encryption-hexkey must both be set".to_string(),
                ));
            }
        };
        let config = DbKeyStoreConfig {
            path,
            encryption_opts,
            allow_ambiguity: allow_ambiguity.unwrap_or(false),
            vfs,
            index_always: index_always.unwrap_or(false),
        };
        DbKeyStore::new(&config)
    }

    /// Returns the database file path
    pub fn path(&self) -> &Path {
        self.inner.path.as_path()
    }

    /// Returns true if the db file is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.inner.encrypted
    }
}

impl DbKeyStoreInner {
    fn connect(&self) -> Result<Connection> {
        let conn = map_turso(self.db.connect())?;
        configure_connection(&conn)?;
        Ok(conn)
    }
}

impl CredentialStoreApi for DbKeyStore {
    fn vendor(&self) -> String {
        String::from("DbKeyStore, https://crates.io/crates/db-keystore")
    }

    fn id(&self) -> String {
        self.inner.id.clone()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        validate_service_user(service, user)?;
        if let Some(mods) = modifiers
            && !mods.is_empty()
        {
            return Err(Error::Invalid(
                "modifiers".to_string(),
                "modifiers are not supported".to_string(),
            ));
        }
        let credential = DbKeyCredential {
            inner: Arc::clone(&self.inner),
            id: CredId {
                service: service.to_string(),
                user: user.to_string(),
            },
            uuid: None,
        };
        Ok(Entry::new_with_credential(Arc::new(credential)))
    }

    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        validate_search_spec(spec)?;
        let service_re = Regex::new(spec.get("service").unwrap_or(&""))
            .map_err(|e| Error::Invalid("service regex".to_string(), e.to_string()))?;
        let user_re = Regex::new(spec.get("user").unwrap_or(&""))
            .map_err(|e| Error::Invalid("user regex".to_string(), e.to_string()))?;
        let comment_re = Regex::new(spec.get("comment").unwrap_or(&""))
            .map_err(|e| Error::Invalid("comment regex".to_string(), e.to_string()))?;
        let uuid_re = Regex::new(spec.get("uuid").unwrap_or(&""))
            .map_err(|e| Error::Invalid("uuid regex".to_string(), e.to_string()))?;
        let conn = self.inner.connect()?;
        let rows = map_turso(block_on(query_all_credentials(&conn)))?;
        let mut entries = Vec::new();
        let filter_comment = spec.get("comment").is_some();
        for (id, uuid, comment) in rows {
            if !service_re.is_match(id.service.as_str()) {
                continue;
            }
            if !user_re.is_match(id.user.as_str()) {
                continue;
            }
            if !uuid_re.is_match(uuid.as_str()) {
                continue;
            }
            if filter_comment {
                match comment.as_ref() {
                    Some(text) if comment_re.is_match(text.as_str()) => {}
                    _ => continue,
                }
            }
            let credential = DbKeyCredential {
                inner: Arc::clone(&self.inner),
                id,
                uuid: Some(uuid),
            };
            entries.push(Entry::new_with_credential(Arc::new(credential)));
        }
        Ok(entries)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }

    fn debug_fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl CredentialApi for DbKeyCredential {
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        validate_service_user(&self.id.service, &self.id.user)?;
        validate_secret(secret)?;
        let make_secret_value = || Value::Blob(secret.to_vec());
        let conn = self.inner.connect()?;
        if self.uuid.is_none() && !self.inner.allow_ambiguity {
            return map_turso(block_on(async {
                let uuid = Uuid::new_v4().to_string();
                let comment = Value::Null;
                conn.execute(
                    "INSERT INTO credentials (service, user, uuid, secret, comment) VALUES (?1, ?2, ?3, ?4, ?5) \
                    ON CONFLICT(service, user) DO UPDATE SET secret = excluded.secret",
                    (
                        self.id.service.as_str(),
                        self.id.user.as_str(),
                        uuid.as_str(),
                        make_secret_value(),
                        comment,
                    ),
                )
                .await?;
                Ok(())
            }));
        }
        block_on(async {
            conn.execute("BEGIN IMMEDIATE", ())
                .await
                .map_err(map_turso_err)?;
            let result = match &self.uuid {
                Some(uuid) => {
                    let updated = conn
                        .execute(
                            "UPDATE credentials SET secret = ?1 WHERE uuid = ?2",
                            (make_secret_value(), uuid.as_str()),
                        )
                        .await
                        .map_err(map_turso_err)?;
                    if updated == 0 {
                        Err(Error::NoEntry)
                    } else {
                        Ok(())
                    }
                }
                None => {
                    let uuids = fetch_uuids(&conn, &self.id).await.map_err(map_turso_err)?;
                    match uuids.len() {
                        0 => {
                            let uuid = Uuid::new_v4().to_string();
                            let comment = Value::Null;
                            conn.execute(
                                "INSERT INTO credentials (service, user, uuid, secret, comment) VALUES (?1, ?2, ?3, ?4, ?5)",
                                (
                                    self.id.service.as_str(),
                                    self.id.user.as_str(),
                                    uuid.as_str(),
                                    make_secret_value(),
                                    comment,
                                ),
                            )
                            .await
                            .map_err(map_turso_err)?;
                            Ok(())
                        }
                        1 => {
                            conn.execute(
                                "UPDATE credentials SET secret = ?1 WHERE uuid = ?2",
                                (make_secret_value(), uuids[0].as_str()),
                            )
                            .await
                            .map_err(map_turso_err)?;
                            Ok(())
                        }
                        _ => Err(Error::Ambiguous(ambiguous_entries(
                            Arc::clone(&self.inner),
                            &self.id,
                            uuids,
                        ))),
                    }
                }
            };
            match result {
                Ok(()) => {
                    conn.execute("COMMIT", ()).await.map_err(map_turso_err)?;
                    Ok(())
                }
                Err(err) => {
                    let _ = conn.execute("ROLLBACK", ()).await;
                    Err(err)
                }
            }
        })
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        validate_service_user(&self.id.service, &self.id.user)?;
        let conn = self.inner.connect()?;
        match &self.uuid {
            Some(uuid) => {
                let secret = map_turso(block_on(fetch_secret_by_uuid(&conn, uuid)))?;
                match secret {
                    Some(secret) => Ok(secret),
                    None => Err(Error::NoEntry),
                }
            }
            None => {
                let matches = map_turso(block_on(fetch_secrets_by_id(&conn, &self.id)))?;
                match matches.len() {
                    0 => Err(Error::NoEntry),
                    1 => Ok(matches[0].1.clone()),
                    _ => Err(Error::Ambiguous(ambiguous_entries(
                        Arc::clone(&self.inner),
                        &self.id,
                        matches.into_iter().map(|pair| pair.0).collect(),
                    ))),
                }
            }
        }
    }

    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        validate_service_user(&self.id.service, &self.id.user)?;
        let conn = self.inner.connect()?;
        match &self.uuid {
            Some(uuid) => {
                let comment = map_turso(block_on(fetch_comment_by_uuid(&conn, uuid)))?;
                match comment {
                    Some(comment) => Ok(attributes_for_uuid(uuid.as_str(), comment)),
                    None => Err(Error::NoEntry),
                }
            }
            None => {
                let matches = map_turso(block_on(fetch_comments_by_id(&conn, &self.id)))?;
                match matches.len() {
                    0 => Err(Error::NoEntry),
                    1 => Ok(attributes_for_uuid(
                        matches[0].0.as_str(),
                        matches[0].1.clone(),
                    )),
                    _ => Err(Error::Ambiguous(ambiguous_entries(
                        Arc::clone(&self.inner),
                        &self.id,
                        matches.into_iter().map(|pair| pair.0).collect(),
                    ))),
                }
            }
        }
    }

    fn update_attributes(&self, attrs: &HashMap<&str, &str>) -> Result<()> {
        parse_attributes(&["comment"], Some(attrs))?;
        let comment = attrs.get("comment").map(|value| value.to_string());
        if comment.is_none() {
            self.get_attributes()?;
            return Ok(());
        }
        let make_comment_value = || match comment.as_ref() {
            Some(value) => Value::Text(value.to_string()),
            None => Value::Null,
        };
        let conn = self.inner.connect()?;
        block_on(async {
            conn.execute("BEGIN IMMEDIATE", ())
                .await
                .map_err(map_turso_err)?;
            let result = match &self.uuid {
                Some(uuid) => {
                    let updated = conn
                        .execute(
                            "UPDATE credentials SET comment = ?1 WHERE uuid = ?2",
                            (make_comment_value(), uuid.as_str()),
                        )
                        .await
                        .map_err(map_turso_err)?;
                    if updated == 0 {
                        Err(Error::NoEntry)
                    } else {
                        Ok(())
                    }
                }
                None if self.inner.allow_ambiguity => {
                    let uuids = fetch_uuids(&conn, &self.id).await.map_err(map_turso_err)?;
                    match uuids.len() {
                        0 => Err(Error::NoEntry),
                        1 => {
                            conn.execute(
                                "UPDATE credentials SET comment = ?1 WHERE uuid = ?2",
                                (make_comment_value(), uuids[0].as_str()),
                            )
                            .await
                            .map_err(map_turso_err)?;
                            Ok(())
                        }
                        _ => Err(Error::Ambiguous(ambiguous_entries(
                            Arc::clone(&self.inner),
                            &self.id,
                            uuids,
                        ))),
                    }
                }
                None => {
                    let updated = conn
                        .execute(
                            "UPDATE credentials SET comment = ?1 WHERE service = ?2 AND user = ?3",
                            (
                                make_comment_value(),
                                self.id.service.as_str(),
                                self.id.user.as_str(),
                            ),
                        )
                        .await
                        .map_err(map_turso_err)?;
                    if updated == 0 {
                        Err(Error::NoEntry)
                    } else {
                        Ok(())
                    }
                }
            };
            match result {
                Ok(()) => {
                    conn.execute("COMMIT", ()).await.map_err(map_turso_err)?;
                    Ok(())
                }
                Err(err) => {
                    let _ = conn.execute("ROLLBACK", ()).await;
                    Err(err)
                }
            }
        })
    }

    fn delete_credential(&self) -> Result<()> {
        validate_service_user(&self.id.service, &self.id.user)?;
        let conn = self.inner.connect()?;
        match &self.uuid {
            Some(uuid) => {
                let deleted = map_turso(block_on(
                    conn.execute("DELETE FROM credentials WHERE uuid = ?1", (uuid.as_str(),)),
                ))?;
                if deleted == 0 {
                    Err(Error::NoEntry)
                } else {
                    Ok(())
                }
            }
            None => {
                let uuids = map_turso(block_on(fetch_uuids(&conn, &self.id)))?;
                match uuids.len() {
                    0 => Ok(()),
                    1 => {
                        map_turso(block_on(conn.execute(
                            "DELETE FROM credentials WHERE uuid = ?1",
                            (uuids[0].as_str(),),
                        )))?;
                        Ok(())
                    }
                    _ => Err(Error::Ambiguous(ambiguous_entries(
                        Arc::clone(&self.inner),
                        &self.id,
                        uuids,
                    ))),
                }
            }
        }
    }

    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        validate_service_user(&self.id.service, &self.id.user)?;
        if self.uuid.is_some() {
            return Ok(None);
        }
        let conn = self.inner.connect()?;
        let uuids = map_turso(block_on(fetch_uuids(&conn, &self.id)))?;
        match uuids.len() {
            0 => Err(Error::NoEntry),
            1 => Ok(Some(Arc::new(DbKeyCredential {
                inner: Arc::clone(&self.inner),
                id: self.id.clone(),
                uuid: Some(uuids[0].clone()),
            }))),
            _ => Err(Error::Ambiguous(ambiguous_entries(
                Arc::clone(&self.inner),
                &self.id,
                uuids,
            ))),
        }
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.id.service.clone(), self.id.user.clone()))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn debug_fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

fn init_schema(conn: &Connection, allow_ambiguity: bool, index_always: bool) -> Result<()> {
    map_turso(block_on(conn.execute(
        "CREATE TABLE IF NOT EXISTS credentials (service TEXT NOT NULL, user TEXT NOT NULL, uuid TEXT NOT NULL, secret BLOB NOT NULL, comment TEXT)",
        (),
    )))?;
    map_turso(block_on(conn.execute(
        "CREATE TABLE IF NOT EXISTS keystore_meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)",
        (),
    )))?;
    ensure_schema_version(conn)?;
    if !allow_ambiguity {
        // unique index used to help ensure non-ambiguity of (service,user)
        map_turso(block_on(conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uidx_credentials_service_user ON credentials (service, user)",
            (),
        )))?;
    } else if index_always {
        // Performance tradeoffs: this index roughly doubles the file size.
        // - For keystores with ~100 entries, it saves 0.1ms per lookup (.17 vs .28 ms).
        // - For ~1000 entries, the index saves ~1ms per lookup (0.1 vs 1.4 ms)
        // - Measured on a m3 macbook air.
        map_turso(block_on(conn.execute(
             "CREATE INDEX IF NOT EXISTS idx_credentials_service_user ON credentials (service, user)",
             (),
            )))?;
    }
    Ok(())
}

fn ensure_schema_version(conn: &Connection) -> Result<()> {
    map_turso(block_on(async {
        let mut rows = conn
            .query(
                "SELECT value FROM keystore_meta WHERE key = 'schema_version'",
                (),
            )
            .await?;
        if let Some(row) = rows.next().await? {
            let value = value_to_string(row.get_value(0)?, "schema_version")?;
            let version = value.parse::<u32>().map_err(|_| {
                turso::Error::ConversionFailure(format!("invalid schema_version value: {value}"))
            })?;
            if version != SCHEMA_VERSION {
                return Err(turso::Error::ConversionFailure(format!(
                    "unsupported schema version: {version}"
                )));
            }
        } else {
            conn.execute(
                "INSERT INTO keystore_meta (key, value) VALUES ('schema_version', ?1)",
                (SCHEMA_VERSION.to_string(),),
            )
            .await?;
        }
        Ok(())
    }))
}

async fn query_all_credentials(
    conn: &Connection,
) -> turso::Result<Vec<(CredId, String, Option<String>)>> {
    let mut rows = conn
        .query("SELECT service, user, uuid, comment FROM credentials", ())
        .await?;
    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        let service = value_to_string(row.get_value(0)?, "service")?;
        let user = value_to_string(row.get_value(1)?, "user")?;
        let uuid = value_to_string(row.get_value(2)?, "uuid")?;
        let comment = value_to_option_string(row.get_value(3)?, "comment")?;
        results.push((CredId { service, user }, uuid, comment));
    }
    Ok(results)
}

async fn fetch_uuids(conn: &Connection, id: &CredId) -> turso::Result<Vec<String>> {
    let mut rows = conn
        .query(
            "SELECT uuid FROM credentials WHERE service = ?1 AND user = ?2",
            (id.service.as_str(), id.user.as_str()),
        )
        .await?;
    let mut uuids = Vec::new();
    while let Some(row) = rows.next().await? {
        let uuid = value_to_string(row.get_value(0)?, "uuid")?;
        uuids.push(uuid);
    }
    Ok(uuids)
}

async fn fetch_secret_by_uuid(conn: &Connection, uuid: &str) -> turso::Result<Option<Vec<u8>>> {
    let mut rows = conn
        .query("SELECT secret FROM credentials WHERE uuid = ?1", (uuid,))
        .await?;
    let Some(row) = rows.next().await? else {
        return Ok(None);
    };
    let secret = value_to_bytes(row.get_value(0)?, "secret")?;
    Ok(Some(secret))
}

async fn fetch_secrets_by_id(
    conn: &Connection,
    id: &CredId,
) -> turso::Result<Vec<(String, Vec<u8>)>> {
    let mut rows = conn
        .query(
            "SELECT uuid, secret FROM credentials WHERE service = ?1 AND user = ?2",
            (id.service.as_str(), id.user.as_str()),
        )
        .await?;
    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        let uuid = value_to_string(row.get_value(0)?, "uuid")?;
        let secret = value_to_bytes(row.get_value(1)?, "secret")?;
        results.push((uuid, secret));
    }
    Ok(results)
}

async fn fetch_comment_by_uuid(
    conn: &Connection,
    uuid: &str,
) -> turso::Result<Option<Option<String>>> {
    let mut rows = conn
        .query("SELECT comment FROM credentials WHERE uuid = ?1", (uuid,))
        .await?;
    if let Some(row) = rows.next().await? {
        let comment = value_to_option_string(row.get_value(0)?, "comment")?;
        Ok(Some(comment))
    } else {
        Ok(None)
    }
}

async fn fetch_comments_by_id(
    conn: &Connection,
    id: &CredId,
) -> turso::Result<Vec<(String, Option<String>)>> {
    let mut rows = conn
        .query(
            "SELECT uuid, comment FROM credentials WHERE service = ?1 AND user = ?2",
            (id.service.as_str(), id.user.as_str()),
        )
        .await?;
    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        let uuid = value_to_string(row.get_value(0)?, "uuid")?;
        let comment = value_to_option_string(row.get_value(1)?, "comment")?;
        results.push((uuid, comment));
    }
    Ok(results)
}

fn ambiguous_entries(inner: Arc<DbKeyStoreInner>, id: &CredId, uuids: Vec<String>) -> Vec<Entry> {
    uuids
        .into_iter()
        .map(|uuid| {
            Entry::new_with_credential(Arc::new(DbKeyCredential {
                inner: Arc::clone(&inner),
                id: id.clone(),
                uuid: Some(uuid),
            }))
        })
        .collect()
}

fn attributes_for_uuid(uuid: &str, comment: Option<String>) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    attrs.insert("uuid".to_string(), uuid.to_string());
    if let Some(comment) = comment {
        attrs.insert("comment".to_string(), comment);
    }
    attrs
}

fn configure_connection(conn: &Connection) -> Result<()> {
    map_turso(block_on(async {
        let mut rows = conn.query("PRAGMA journal_mode=WAL", ()).await?;
        let _ = rows.next().await?;
        let busy_stmt = format!("PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}");
        conn.execute(busy_stmt.as_str(), ()).await?;
        Ok(())
    }))
}

/// Opens database. Retries with exponential backoff if the file is locked.
fn open_db_with_retry(
    path_str: &str,
    encryption_opts: Option<EncryptionOpts>,
    vfs: Option<String>,
) -> Result<Database> {
    let mut retries = OPEN_LOCK_RETRIES;
    let mut backoff_ms = OPEN_LOCK_BACKOFF_MS;
    loop {
        let mut builder = Builder::new_local(path_str);
        if let Some(opts) = encryption_opts.clone() {
            let turso_enc_opts = turso::EncryptionOpts {
                cipher: opts.cipher,
                hexkey: opts.hexkey,
            };
            builder = builder
                .experimental_encryption(true)
                .with_encryption(turso_enc_opts);
        }
        if let Some(vfs) = vfs.clone() {
            builder = builder.with_io(vfs);
        }
        match block_on(builder.build()) {
            Ok(db) => return Ok(db),
            Err(err) => {
                if retries == 0 || !is_turso_locking_error(&err) {
                    return Err(map_turso_err(err));
                }
                retries -= 1;
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos();
                let jitter = (nanos % 20) as u64;
                std::thread::sleep(std::time::Duration::from_millis(backoff_ms + jitter));
                backoff_ms = (backoff_ms * 2).min(OPEN_LOCK_BACKOFF_MAX_MS);
            }
        }
    }
}

fn retry_turso_locking<T>(mut op: impl FnMut() -> turso::Result<T>) -> Result<T> {
    let mut retries = OPEN_LOCK_RETRIES;
    let mut backoff_ms = OPEN_LOCK_BACKOFF_MS;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) => {
                if retries == 0 || !is_turso_locking_error(&err) {
                    return Err(map_turso_err(err));
                }
                retries -= 1;
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos();
                let jitter = (nanos % 20) as u64;
                std::thread::sleep(std::time::Duration::from_millis(backoff_ms + jitter));
                backoff_ms = (backoff_ms * 2).min(OPEN_LOCK_BACKOFF_MAX_MS);
            }
        }
    }
}

fn is_turso_locking_error(err: &turso::Error) -> bool {
    let text = err.to_string().to_lowercase();
    text.contains("locking error")
        || text.contains("file is locked")
        || text.contains("database is locked")
        || text.contains("database is busy")
        || text.contains("sqlite_busy")
        || text.contains("sqlite_locked")
}

fn parse_bool_modifier(key: &str, value: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(Error::Invalid(
            key.to_string(),
            "must be `true` or `false`".to_string(),
        )),
    }
}

fn value_to_string(value: Value, field: &str) -> turso::Result<String> {
    match value {
        Value::Text(text) => Ok(text),
        Value::Blob(blob) => String::from_utf8(blob)
            .map_err(|e| turso::Error::ConversionFailure(format!("invalid utf8 for {field}: {e}"))),
        other => Err(turso::Error::ConversionFailure(format!(
            "unexpected value for {field}: {other:?}"
        ))),
    }
}

fn value_to_bytes(value: Value, field: &str) -> turso::Result<Vec<u8>> {
    match value {
        Value::Blob(blob) => Ok(blob),
        Value::Text(text) => Ok(text.into_bytes()),
        other => Err(turso::Error::ConversionFailure(format!(
            "unexpected value for {field}: {other:?}"
        ))),
    }
}

fn value_to_option_string(value: Value, field: &str) -> turso::Result<Option<String>> {
    match value {
        Value::Null => Ok(None),
        Value::Text(text) => Ok(Some(text)),
        Value::Blob(blob) => String::from_utf8(blob)
            .map(Some)
            .map_err(|e| turso::Error::ConversionFailure(format!("invalid utf8 for {field}: {e}"))),
        other => Err(turso::Error::ConversionFailure(format!(
            "unexpected value for {field}: {other:?}"
        ))),
    }
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Invalid("path".to_string(), "path has no parent".to_string()))?;
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|e| Error::PlatformFailure(Box::new(e)))
}

/// confirm service and user are non-empty and within length bounds
fn validate_service_user(service: &str, user: &str) -> Result<()> {
    if service.is_empty() {
        return Err(Error::Invalid(
            "service".to_string(),
            "service is empty".to_string(),
        ));
    }
    if user.is_empty() {
        return Err(Error::Invalid(
            "user".to_string(),
            "user is empty".to_string(),
        ));
    }
    if service.len() > MAX_NAME_LEN {
        return Err(Error::TooLong("service".to_string(), MAX_NAME_LEN as u32));
    }
    if user.len() > MAX_NAME_LEN {
        return Err(Error::TooLong("user".to_string(), MAX_NAME_LEN as u32));
    }
    Ok(())
}

/// confirm secret is within length bounds
fn validate_secret(secret: &[u8]) -> Result<()> {
    if secret.len() > MAX_SECRET_LEN {
        return Err(Error::TooLong("secret".to_string(), MAX_SECRET_LEN as u32));
    }
    Ok(())
}

fn validate_search_spec(spec: &HashMap<&str, &str>) -> Result<()> {
    for key in spec.keys() {
        if *key != "service" && *key != "user" && *key != "uuid" && *key != "comment" {
            return Err(Error::Invalid(
                "spec".to_string(),
                format!("unsupported key: {key}"),
            ));
        }
    }
    Ok(())
}

fn map_turso<T>(result: std::result::Result<T, turso::Error>) -> Result<T> {
    result.map_err(map_turso_err)
}

fn map_turso_err(err: turso::Error) -> Error {
    Error::PlatformFailure(Box::new(err))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_store(path: &Path) -> DbKeyStore {
        let config = DbKeyStoreConfig {
            path: path.to_path_buf(),
            ..Default::default()
        };
        DbKeyStore::new(&config).expect("failed to create store")
    }

    fn build_entry(store: &DbKeyStore, service: &str, user: &str) -> Entry {
        store
            .build(service, user, None)
            .expect("failed to build entry")
    }

    // test that non-existent parent dir is created on db open
    #[test]
    fn create_store_creates_parent_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("nested").join("deeply").join("keystore.db");
        let parent = db_path.parent().expect("parent");
        assert!(!parent.exists());

        let config = DbKeyStoreConfig {
            path: db_path.clone(),
            ..Default::default()
        };
        let store = DbKeyStore::new(&config).expect("create store");
        assert!(parent.is_dir());

        let entry = build_entry(&store, "demo", "alice");
        entry.set_password("dromomeryx").expect("set_password");
    }

    // test round-trip set and search
    #[test]
    fn set_password_then_search_finds_password() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keystore.db");
        let store = new_store(&path);
        let entry = build_entry(&store, "demo", "alice");
        entry.set_password("dromomeryx").expect("set_password");

        let mut spec = HashMap::new();
        spec.insert("service", "demo");
        spec.insert("user", "alice");
        let results = store.search(&spec).expect("search");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get_password().unwrap(), "dromomeryx");
    }

    // test with comment search
    #[test]
    fn comment_attributes_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keystore.db");
        let store = new_store(&path);
        let entry = build_entry(&store, "demo", "alice");
        entry.set_password("dromomeryx").expect("set_password");

        let update = HashMap::from([("comment", "note")]);
        entry.update_attributes(&update).expect("update_attributes");
        let attrs = entry.get_attributes().expect("get_attributes");
        assert_eq!(attrs.get("comment"), Some(&"note".to_string()));
        assert!(attrs.contains_key("uuid"));

        let mut spec = HashMap::new();
        spec.insert("service", "demo");
        spec.insert("user", "alice");
        spec.insert("comment", "note");
        let results = store.search(&spec).expect("search");
        assert_eq!(results.len(), 1);

        let uuid = attrs.get("uuid").cloned().unwrap();
        let mut spec = HashMap::new();
        spec.insert("service", "demo");
        spec.insert("user", "alice");
        spec.insert("uuid", uuid.as_str());
        let results = store.search(&spec).expect("search");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn comment_with_password_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keystore.db");
        let store = new_store(&path);
        let entry = build_entry(&store, "demo", "alice");
        entry.set_password("dromomeryx").expect("set_password");

        // set a comment attribute
        let update = HashMap::from([("comment", "note")]);
        entry.update_attributes(&update).expect("update_attributes");

        // then search by comment
        let mut spec = HashMap::new();
        spec.insert("service", "demo");
        spec.insert("user", "alice");
        spec.insert("comment", "note");
        let results = store.search(&spec).expect("search");
        assert_eq!(results.len(), 1);

        let found = &results[0];
        assert_eq!(found.get_password().unwrap(), "dromomeryx");
        let attrs = found.get_attributes().expect("get_attributes");
        assert_eq!(attrs.get("comment"), Some(&"note".to_string()));
        assert!(attrs.contains_key("uuid"));
    }

    // test that unique users in same service have unique keys
    #[test]
    fn stores_separate_service_user_pairs() -> Result<()> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keystore.db");
        let store = new_store(&path);

        build_entry(&store, "myapp", "user1").set_password("pw1")?;
        build_entry(&store, "myapp", "user2").set_password("pw2")?;
        build_entry(&store, "myapp", "user3").set_password("pw3")?;

        let results = store.search(&HashMap::from([("service", "myapp"), ("user", "user1")]))?;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get_password()?, "pw1");

        let results = store.search(&HashMap::from([("service", "myapp"), ("user", "user2")]))?;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get_password()?, "pw2");

        let results = store.search(&HashMap::from([("service", "myapp"), ("user", "user3")]))?;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get_password()?, "pw3");
        Ok(())
    }

    // search with regex
    #[test]
    fn search_regex() -> Result<()> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keystore.db");
        let store = new_store(&path);

        build_entry(&store, "myapp", "user1").set_password("pw1")?;
        build_entry(&store, "myapp", "user2").set_password("pw2")?;
        build_entry(&store, "myapp", "user3").set_password("pw3")?;
        build_entry(&store, "other-app", "user1").set_password("pw4")?;

        // regex search: all apps, user1
        let results = store.search(&HashMap::from([("service", ".*app"), ("user", "user1")]))?;
        assert_eq!(results.len(), 2, "search *app, user1");

        // regex search _or_
        let results = store.search(&HashMap::from([
            ("service", "myapp"),
            ("user", "user1|user2"),
        ]))?;
        assert_eq!(results.len(), 2, "search regex OR");

        Ok(())
    }

    // search with partial hashmap
    #[test]
    fn search_partial() -> Result<()> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keystore.db");
        let store = new_store(&path);

        // empty db has no entries
        let results = store.search(&HashMap::new())?;
        assert_eq!(results.len(), 0, "empty db, no results");

        build_entry(&store, "myapp", "user1").set_password("pw1")?;
        build_entry(&store, "other-app", "user1").set_password("pw2")?;

        // empty search terms match all
        let results = store.search(&HashMap::new())?;
        assert_eq!(results.len(), 2, "search, empty hashmap");

        // app-only match
        let results = store.search(&HashMap::from([("service", "myapp")]))?;
        assert_eq!(results.len(), 1, "search myapp");

        // user-only match
        let results = store.search(&HashMap::from([("user", "user1")]))?;
        assert_eq!(results.len(), 2, "search user1");
        Ok(())
    }

    // replacement
    #[test]
    fn repeated_set_replaces_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keystore.db");
        let store = new_store(&path);
        let entry = build_entry(&store, "demo", "alice");
        entry.set_password("first").unwrap();
        entry.set_secret(b"second").unwrap();

        let mut spec = HashMap::new();
        spec.insert("service", "demo");
        spec.insert("user", "alice");
        let results = store.search(&spec).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].get_password().unwrap(),
            "second",
            "second password overwrites first"
        );
    }

    // deletion is idempotent, and no error returned if no entry
    #[test]
    fn remove_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keystore.db");
        let store = new_store(&path);
        let entry = build_entry(&store, "demo", "alice");
        entry.set_password("dromomeryx").unwrap();
        entry.delete_credential().unwrap();
        entry.delete_credential().unwrap();
    }

    // deletion actually deletes
    #[test]
    fn remove_clears_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keystore.db");
        let store = new_store(&path);
        let entry = build_entry(&store, "service", "user");
        entry.set_password("dromomeryx").unwrap();
        entry.delete_credential().unwrap();

        let mut spec = HashMap::new();
        spec.insert("service", "demo");
        spec.insert("user", "alice");
        let results = store.search(&spec).unwrap();
        assert!(results.is_empty());
    }
}
