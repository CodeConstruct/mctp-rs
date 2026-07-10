#!/usr/bin/env bash

set -v
set -e

export CARGO_TARGET_DIR="$PWD/target/ci"

rustup target add thumbv7em-none-eabihf
rustup component add rustfmt clippy

export RUSTDOCFLAGS='-D warnings'
export RUSTFLAGS="-D warnings"

cargo fmt -- --check

# Check everything first
cargo check --all-targets --locked
if [ -z "$NO_CLIPPY" ]; then
    cargo clippy --all-targets
fi

# stable, std
cargo build --release
cargo test

# stable, no_std
NOSTD_CRATES="mctp pldm pldm-fw pldm-platform pldm-file"
for c in $NOSTD_CRATES; do
    (
    cargo build -p $c --target thumbv7em-none-eabihf --no-default-features
    )
done
ALLOC_CRATES="pldm pldm-platform pldm-file"
for c in $ALLOC_CRATES; do
    (
    cargo build -p $c --target thumbv7em-none-eabihf --no-default-features --features alloc
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

FEATURES_ASYNC="async"
FEATURES_SYNC=""

declare -a FEATURES=(
    "$FEATURES_SYNC"
    "$FEATURES_ASYNC"
)

# mctp-estack, sync and async
(
cd mctp-estack
for feature in "${FEATURES[@]}"; do
    cargo test --features="$feature"
done;
)

# Linux programs and examples
# Tested individually to ensure each defines necessary features itself
LINUX_PROGRAMS="mctp-linux pldm-platform-util pldm-fw-cli mctp-standalone pldm-file pldm-platform"
for c in $LINUX_PROGRAMS; do
    cargo check -p $c --all-targets
done

# run cargo doc tests
for feature in "${FEATURES[@]}"; do
    cargo doc --features="$feature"
done;

echo success
