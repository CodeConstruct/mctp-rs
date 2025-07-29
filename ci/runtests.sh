#!/bin/bash

set -v
set -e

export CARGO_TARGET_DIR=target/ci

rustup target add thumbv7em-none-eabihf
rustup component add rustfmt clippy

export RUSTDOCFLAGS='-D warnings'
export RUSTFLAGS="-D warnings"

cargo fmt -- --check

# Check everything first
cargo check --all-targets --locked
cargo clippy --all-targets

# stable, std
cargo build --release
cargo test

# stable, no_std
NOSTD_CRATES="mctp pldm pldm-fw"
for c in $NOSTD_CRATES; do
    (
    cd $c
    cargo build --target thumbv7em-none-eabihf --no-default-features --release
    )
done

# mctp-estack combinations, defmt and log
(
cd mctp-estack
cargo build --target thumbv7em-none-eabihf --features defmt --no-default-features
cargo build --features log
)

# mctp-usb-embassy combinations, defmt and log
(
cd mctp-usb-embassy
cargo build --target thumbv7em-none-eabihf --features defmt --no-default-features
cargo build --features log
)

cargo doc

echo success
