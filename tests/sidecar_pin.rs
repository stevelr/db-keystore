//! Pins the turso version together with the sidecar suffix set (feedback B3).
//!
//! db-keystore pre-creates a database's sidecar files with mode `0600` so
//! credential plaintext in the WAL is never world-readable, and its cleanup
//! and verification logic iterates the same set (`SIDECAR_SUFFIXES` in
//! `src/rekey.rs`). That set is correct for turso 0.7.0 by manual
//! verification (`coordination_path_for_wal_path`). If a turso upgrade
//! renames or adds a sidecar, the pre-creation guarantee would silently no
//! longer cover the new file. These tests therefore fail on any turso bump
//! until the set is re-verified and the pin below is updated.

use std::collections::HashMap;

use db_keystore::{DbKeyStore, DbKeyStoreConfig};
use keyring_core::api::CredentialStoreApi;

/// Update only after re-verifying the sidecar file set against the new turso
/// (see module docs), and keep `PINNED_SIDECAR_SUFFIXES` and
/// `SIDECAR_SUFFIXES` in `src/rekey.rs` in sync with what you find.
const PINNED_TURSO_VERSION: &str = "0.7.0";

/// Must match `SIDECAR_SUFFIXES` in `src/rekey.rs`.
const PINNED_SIDECAR_SUFFIXES: [&str; 2] = ["-wal", "-tshm"];

#[test]
fn turso_version_is_pinned_until_sidecar_set_reverified() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"))
        .expect("read Cargo.lock");
    let mut lines = lock.lines();
    let mut version = None;
    while let Some(line) = lines.next() {
        if line.trim() == "name = \"turso\"" {
            version = lines.next().and_then(|l| {
                l.trim()
                    .strip_prefix("version = \"")
                    .and_then(|v| v.strip_suffix('"'))
            });
            break;
        }
    }
    let version = version.expect("turso entry in Cargo.lock");
    assert_eq!(
        version, PINNED_TURSO_VERSION,
        "turso version changed ({PINNED_TURSO_VERSION} -> {version}): re-verify the sidecar \
         file set against the new turso (coordination_path_for_wal_path), update \
         SIDECAR_SUFFIXES in src/rekey.rs and PINNED_SIDECAR_SUFFIXES in this test if it \
         changed, then update PINNED_TURSO_VERSION here"
    );
}

// Empirical half of the pin: every file the database layer creates next to a
// live, written-to database must be covered by the pinned suffix set. A turso
// that starts creating a differently-named sidecar fails here even if the
// version pin above was updated without re-verifying the set.
#[test]
fn observed_sidecars_are_covered_by_pinned_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("pin.db");
    let mut observed = Vec::new();
    {
        let store = DbKeyStore::new(DbKeyStoreConfig {
            path: db_path,
            ..Default::default()
        })
        .expect("store");
        let entry = store
            .build("svc", "user", Some(&HashMap::from([("comment", "c")])))
            .expect("build");
        entry.set_password("pw").expect("set_password");

        // observe while the writing session is live, when sidecars exist
        for file in std::fs::read_dir(dir.path()).expect("read_dir") {
            let name = file.expect("entry").file_name();
            let name = name.to_str().expect("utf8").to_string();
            if name != "pin.db" {
                observed.push(name);
            }
        }
    }
    assert!(
        observed.iter().any(|name| name == "pin.db-wal"),
        "expected a WAL sidecar during a write session, saw {observed:?} \
         (did turso change its WAL naming?)"
    );
    for name in &observed {
        let suffix = name.strip_prefix("pin.db").unwrap_or_else(|| {
            panic!("unexpected non-sidecar file '{name}' created next to the database")
        });
        assert!(
            PINNED_SIDECAR_SUFFIXES.contains(&suffix),
            "database layer created sidecar '{name}' with suffix '{suffix}' not covered by \
             the pinned set {PINNED_SIDECAR_SUFFIXES:?}: its mode is not pinned to 0600 at \
             creation; re-verify and update SIDECAR_SUFFIXES in src/rekey.rs"
        );
    }
}
