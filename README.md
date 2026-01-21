# db-keystore

SQLite-backed credential store for the `keyring-core` API, built on Turso.
It implements `CredentialStoreApi` and `CredentialApi`, so it can be used
anywhere a `keyring_core::api::CredentialStore` is accepted (including
`use_named_store_with_modifiers`).

## Features

- File-backed SQLite storage with optional encryption.
- WAL + busy timeout for safety in multi-process environments.
- Optional uniqueness enforcement on `(service, user)`.
- UUID and optional `comment` attributes exposed via the credential API.
- Search with regex filters over `service`, `user`, `uuid`, and `comment`.

## Configuration

You can configure the store either with `DbKeyStoreConfig` or with modifiers.

### DbKeyStoreConfig

```rust
use db_keystore::{DbKeyStore, DbKeyStoreConfig, EncryptionOpts};

let config = DbKeyStoreConfig {
    path: "keystore.db".into(),
    ..Default::default()
};

let store = DbKeyStore::new(&config).expect("store");
```

With encryption:

```rust
use db_keystore::{DbKeyStore, DbKeyStoreConfig, EncryptionOpts};

let config = DbKeyStoreConfig {
    path: "keystore.db".into(),
    encryption_opts: Some(EncryptionOpts {
        cipher: "aegis256".to_string(),
        hexkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    }),
    ..Default::default()
};
let store = DbKeyStore::new(&config).expect("store");
```

### Modifiers

`DbKeyStore::new_with_modifiers` supports the following keys:

- `path` (required): path to the SQLite database file.
- `encryption-cipher` or `cipher`: cipher name (requires `encryption-hexkey`).
- `encryption-hexkey` or `hexkey`: encryption key as hex (requires `cipher`).
- `allow-ambiguity` or `allow_ambiguity`: `"true"` or `"false"` (default `false`).
- `vfs`: VFS selection (`"memory"`, `"io_uring"`, or `"syscall"`).

```rust
use std::collections::HashMap;
use db_keystore::DbKeyStore;

let modifiers = HashMap::from([
    ("path", "keystore.db"),
    ("allow-ambiguity", "true"),
]);
let store = DbKeyStore::new_with_modifiers(&modifiers).expect("store");
```

## Search

Search expects a map of regex filters. Supported keys: `service`, `user`,
`uuid`, `comment`. If `comment` is provided, results must have a matching
comment; otherwise it is ignored.

```rust
use std::collections::HashMap;

let spec = HashMap::from([
    ("service", "my-service"),
    ("user", "alice"),
]);
let entries = store.search(&spec).expect("search");
```

## Notes

- Secrets are stored as UTF-8 text and limited to 8KB each. Service and user names limited to 128 chars each. These are somewhat arbitrary, to prevent accidental blow-up of the database.
- `allow_ambiguity = false` enforces a unique index on `(service, user)` and uses UPSERT for `set_secret`.
- When ambiguity is allowed, operations may return `Error::Ambiguous` if multiple credentials match a single `(service, user)` pair.

## License

MIT OR Apache-2.0
