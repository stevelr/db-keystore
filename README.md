# db-keystore

Platform-independent, SQLite-backed credential store for the `keyring-core` API, with optional encryption-at-rest. Built with [turso](https://crates.io/crates/turso).

This crate implements [`keyring-core`](https://crates.io/crates/keyring-core)::[`CredentialStoreApi`](https://docs.rs/keyring-core/latest/keyring_core/api/trait.CredentialStoreApi.html) and [`CredentialApi`](https://docs.rs/keyring-core/latest/keyring_core/api/trait.CredentialApi.html).

## Features

- Rust-native SQLite implementation by [turso](https://crates.io/crates/turso), with open source encryption.
- WAL + busy timeout for safety in multi-process environments.
- Optional uniqueness enforcement on `(service, user)`.
- UUID and optional `comment` attributes exposed via the credential API.
- Search with regex filters over `service`, `user`, `uuid`, and `comment`.
- Several [Examples](./examples)

## Configuration

Keystore settings can be configured either with modifiers (string key-value pairs, for use with the `keyring` crate), or `struct DbKeyStoreConfig`.

Modifier keys (all optional):

- **`path`**: path to the SQLite database file. Defaults to `$XDG_STATE_HOME/keystore.db` if $XDG_STATE_HOME is defined, or `$HOME/.local/state/keystore.db`
- **`allow-ambiguity`** (alias `allow_ambiguity`): `"true"` or `"false"`. Default `false`. Allows storage of more than one match for the pair (service,user). Individual pairs can be identified by the unique uuid or comment. When false, a `UNIQUE` index is created to enforce uniqueness.
- **`encryption-cipher`** (alias `cipher`): Cipher name (requires `hexkey`). See below for list of supported ciphers.
- **`encryption-hexkey`** (alias `hexkey`): Encryption key as 64 hex digits (256-bit key) or 32 hex digits (128-bit key) (requires `cipher`).
- **`index-always`** (alias `index_always`): `"true"` or `"false"`. Default `false`. Adds an index on `(service,user)` even when `allow-ambiguity` is true.
- **`vfs`**: Optional VFS selection (`"memory"`, `"syscall"`, or `"io_uring"`).
  - "memory": In-memory database. Data is entirely in RAM, and data is lost when process exits. When vfs=memory, `path` and encryption options are ignored.
  - "syscall": Generic syscall backend. Uses standard POSIX system calls for file I/O. This is the most portable mode.
  - "io_uring": Linux io_uring backend. Uses Linux's modern async I/O interface for better performance. Only available on Linux.

Entry modifiers supported by `build`:

- **`uuid`**: Explicit credential UUID (allows creating ambiguous entries when allowed).
- **`comment`**: Initial comment value stored with the credential.

## Examples

### Configure and open

```rust
use db_keystore::{DbKeyStore, DbKeyStoreConfig, EncryptionOpts};
use keyring_core::{Result, api::CredentialStoreApi};
use std::{collections::HashMap, path::Path, sync::Arc};

/// Open in default location (~/.local/state/keystore.db)
fn open_db() -> Result<Arc<DbKeyStore>> {
    let config = DbKeyStoreConfig::default();
    DbKeyStore::new(&config)
}

/// Open encrypted database in custom folder
fn open_encrypted(dir: &Path, hexkey: &str) -> Result<Arc<DbKeyStore>> {
    let config = DbKeyStoreConfig {
        path: dir.join("keystore.db"),
        encryption_opts: Some(EncryptionOpts::new("aegis256", hexkey)),
        ..Default::default()
    };
    DbKeyStore::new(&config)
}

/// Open in-memory db
fn open_in_memory() -> Result<Arc<DbKeyStore>> {
    let config = DbKeyStoreConfig {
        vfs: Some("memory".to_string()),
        ..Default::default()
    };
    DbKeyStore::new(&config)
}
```

### Save and lookup secrets

```rust
use db_keystore::{DbKeyStore, DbKeyStoreConfig, EncryptionOpts};
use keyring_core::{Entry, Result, api::CredentialStoreApi};
use std::{collections::HashMap, sync::Arc};

fn save_password(db: Arc<DbKeyStore>, service: &str, user: &str, password: &str) -> Result<()> {
    // use `set_password` to store secrets that are utf8 strings
    // service and user must be non-empty
    let entry = db.build(service, user, None)?;
    entry.set_password(password)
}

fn save_secret(db: Arc<DbKeyStore>, service: &str, user: &str, secret: &[u8]) -> Result<()> {
    // use `set_secret` to store any binary secret (up to 64KiB)
    // service and user must be non-empty
    let bin_entry = db.build(service, user, None)?;
    bin_entry.set_secret(secret)
}

// Note: db-keystore zeroizes temporary secret buffers it owns, but secrets passed into Turso
// may be copied internally and are not currently zeroized on drop.


/// Verify secret. Returns true if there is a matching password for the service+user
fn verify_secret(db: Arc<DbKeyStore>, service: &str, user: &str, expected: &[u8]) -> Result<bool> {
    let spec = HashMap::from([("service", service), ("user", user)]);
    let results = db.search(&spec)?;
    // check all entries in case db has allow_ambiguity
    for entry in results.iter() {
        if entry.get_secret()? == expected {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Search using optional regex filters. Returns matches
fn search(
    db: Arc<DbKeyStore>, service_re: Option<&str>, user_re: Option<&str>,
    uuid_re: Option<&str>, comment_re: Option<&str>,
) -> Result<Vec<Entry>> {
    let mut spec = HashMap::new();
    /// `search` supports keys: `service`, `user`, `uuid`, `comment`.
    if let Some(service) = service_re { spec.insert("service", service); }
    if let Some(user) = user_re { spec.insert("user", user); }
    if let Some(uuid) = uuid_re { spec.insert("uuid", uuid); }
    if let Some(comment) = comment_re { spec.insert("comment", comment); }
    db.search(&spec)
}
```

### Debugging tool

The `dump-db-keystore` debugging tool prints all entries in the keystore. It accepts an optional path and modifier key/value pairs. For encrypted databases, args must include `cipher` and `hexkey`.

```sh
cargo run --bin dump-db-keystore -- path=/tmp/keystore.db cipher=aegis256 hexkey=...
```

## Encryption

### Supported ciphers

`aegis256` is recommended for most applications. See [Turso Database Encryption](https://docs.turso.tech/tursodb/encryption) for more information about available ciphers and recommendations.

| Key length | Aegis                                   | AES                     |
| ---------- | --------------------------------------- | ----------------------- |
| 128-bit    | aegis128l<br/>aegis128x2<br/>aegis128x4 | aes128gcm (AES-128-GCM) |
| 256-bit    | aegis256<br/>aegis256x2<br/>aegis256x4  | aes256gcm (AES-256-GCM) |

### Key generation

```sh
# generate 256-bit key as 64 hex digits
openssl rand -hex 32
# generate 128-bit key as 32 hex digits
openssl rand -hex 16

```

```rust
/// generate 256-bit key as 64 hex digits
fn generate_key() -> String {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    hex::encode(key)
}
```

**Important:** Store your encryption key securely. If you lose the key, your encrypted data cannot be recovered.

### Encryption Security

The ciphers are considered strong modern AEAD-based ciphers. The database is encrypted at the page level (default page size 4096 bytes), where each page has a unique nonce. The first 100 bytes, containing a Turso version header and sqlite metadata, are not encrypted.

When using this or any encrypted storage, keep in mind that the greatest risks for stored secrets are usually related to key generation and key management:

- Low entropy keys can enable brute-force attacks.
- Reusing the same key across databases increases the blast radius if a key leaks.
- Generating keys from user input without a strong KDF (Argon2/scrypt) weakens security.
- Storing encryption keys on disk with the database (or leaked in logs or environment) diminishes the benefits of encryption.

## Release Notes (0.3.0)

- `new_with_modifiers` now returns `Result<Arc<DbKeyStore>>` instead of `Result<DbKeyStore>`.

## Release Notes (0.2.2)

### Crash on incorrect decryption key

In turso v0.4.3 (used in db-keystore 0.2.x and 0.3.0), attempting to open an encrypted database with the wrong key panics. The panic is fixed with turso [PR 4670](https://github.com/tursodatabase/turso/pull/4670), merged into the main branch on 2026-01-15. After this is released on crates.io, we'll release an updated db-keystore.

A potential work-around is to catch the panic. [One of the examples](./examples/encrypted_wrongkey.rs) shows how to catch the panic.

### Schema version

Schema version stored to enable future schema migrations.

### Length limits

Secrets are limited to 65536 bytes, and service and user names are limited to 1024 characters each. These limits are somewhat arbitrary, sanity checks to prevent accidental blow-up of the database. If you need longer keys, submit an issue, and we can increase the length or make it a config setting.

### Ambiguity and database size

When `allow_ambiguity` is false (the default), the pair `(service,user)` is required to be unique and enforced in the database:

- a UNIQUE index is created on the `service, user` columns
- UPSERT is used for `set_secret` and `set_password`.
- operations return `Error::Ambiguous` if multiple credentials match a single `(service, user)` pair.

If `allow_ambiguity` is true, the UNIQUE index is not created. If you expect the keystore to hold ~1000 or more secrets, consider setting `DbKeyStoreConfig::index_always` to create an index on (service,user) to improve lookup performance. The index isn't normally created because it can roughly double the size of the database, and for small keystores doesn't make a significant difference for latency. This is an edge case, as `allow_ambiguity` is default false and does use an index. There are tradeoffs - benchmark on your target platform.

## Testing

```sh
# Run unit tests
# Performance and stress tests skipped to avoid extra wear on SSDs
cargo test -- --nocapture

# Include performance tests.
# To adjust number of iterations, search for "count =" in tests/stress.rs
PERF_INDEX=1 cargo test -- --nocapture

# Include stress tests with multi-process locking and transactions.
# To adjust duration of stress test, change DEFAULT_STRESS_SECONDS
cargo test -- --nocapture --ignored
```

## License

MIT OR Apache-2.0
