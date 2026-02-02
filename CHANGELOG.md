# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [0.4.0] - 2026-02-02

### Breaking

- `DbKeyStore::new` requires `DbKeyStoreConfig` instead of `&DbKeyStoreConfig`.
- All input uuids are converted to lowercase and checked for uuid syntax, returning Error::Invalid for incorrect format.

### Added

- binary db-keystore maintenance/admin utility
- added msrv declaration (1.88)
- bumped turso dependency to 0.4.4

### Changed

- Changed uuid generation from v4 to v7 so ambiguous entries can be sorted by creation time (only applies to automatically inserted uuids, which are generated with uuid::now_v7()).
- Empty comment strings are normalized to NULL on insert/update; comment search with empty string now matches NULL/empty comments only.
- Use zeroize internally to prevent secrets from leaking into heap
- moved dump-db-keystore to examples

### Fixed

- Scoped uuid-based operations to `service` and `user` to avoid cross-credential collisions when uuids are not unique. (Uuid collisions are still very unlikely).

### Documentation

- Updated README and examples.

## [0.3.1] - 2026-01-28

### Added

- Allow `build` modifiers `uuid` and `comment`, enabling explicit UUID creation and initial comment storage.
- New tests for ambiguity handling, shared credentials, in-memory store round-trip, and comment modifiers.
- Documentation for vfs options
- Added impl Debug for DbKeyStore

### Changed

- Modifier/spec validation now uses `parse_attributes`, including boolean parsing.
- Consolidated credential fetch queries to reduce duplication.
- Updated docs to describe `index-always` and build modifiers.
- Clarified that memory vfs ignores path and encryption keys.

### Breaking

- `new` returns `Result<Arc<DbKeyStore>>` instead of `Result<DbKeyStore>`
- `delete_credential` now returns `NoEntry` when no matching credential exists (was idempotent and returned Ok).

## [0.3.0] - 2026-01-27

### Changed

- `new_with_modifiers` returns `Result<Arc<DbKeyStore>>` instead of `Result<DbKeyStore>`

  This may or may not be a breaking change, depending on how it's used. Bumping minor version to follow strict semver.

## [0.2.2] - 2026-01-25

### Added

- Improved documentation and added examples
- Added DbKeyStore getters `path()` and `is_encrypted()`
- Added `encrypted` and `path` fields to inner struct so they appear in Debug and Display impl
- Added `dump-db-keystore` debugging utility (bin/)
- Added schema version metadata table for future migrations

### Changed

- Added crate version and enc:bool to DbKeyStore `id()` response
- Exported `default_path()` as a public function
- Secrets no longer restricted to UTF-8 text - any bytes up to max length supported
- Clearer controls for performance and stress tests

### Fixed

- `dump-db-keystore` now honors `path=...` arguments
- Encrypted example now reopens with the correct key
- Stress test children remove temp database files when temp dir is provided

## [0.2.0] - 2026-01-20

- initial github release
