#!/bin/bash

set -v
set -e

export CARGO_TARGET_DIR=target/ci

rustup target add thumbv7em-none-eabihf
rustup component add rustfmt

export RUSTDOCFLAGS='-D warnings'
export RUSTFLAGS="-D warnings"

cargo fmt -- --check

# Check everything first
cargo check --all-targets

# stable, std
cargo build --release --features mctp-estack/log
cargo test --features mctp-estack/log

# stable, no_std
NOSTD_CRATES="mctp pldm pldm-fw"
for c in $NOSTD_CRATES; do
    (
    cd $c
    cargo build --target thumbv7em-none-eabihf --no-default-features --release
    )
done

# mctp-estack combinations
(
cd mctp-estack
cargo build --target thumbv7em-none-eabihf --features defmt --no-default-features
cargo build --features log
)

# not a workspace
(
cd mctp-usb-embassy
cargo build --target thumbv7em-none-eabihf --features defmt --no-default-features
cargo build --features log
cargo doc
)

cargo doc --features mctp-estack/log

echo success
