# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

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
