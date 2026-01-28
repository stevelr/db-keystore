_default:
    just --list

check:
    cargo clippy -- -D warnings
    rustfmt --edition 2024 --check src/*.rs
    cargo test
    typos
    cspell .
