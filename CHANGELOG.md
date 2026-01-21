# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

### Added

- added DbKeyStore getters path() and is_encrypted()
- added fields 'encrypted' and 'path' to inner struct so they appear in Debug and Display impl
- debugging utility `dump-db-keystore` to dump keys

### Changed

- added crate version and enc:bool to DbKeyStore id() response
- default_path() is now exported as crate public function

## [0.2.0] - 2025-01-20

- initial github release
