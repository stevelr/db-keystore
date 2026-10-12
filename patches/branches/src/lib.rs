//! Semver shim: re-exports `branches` 0.5 under a 0.4-compatible version so
//! `turso_core` (which requires `branches ^0.4.3`) builds on current nightly.
#![no_std]

pub use branches::*;
