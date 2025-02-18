#!/bin/bash

set -v
set -e

rustup target add thumbv7em-none-eabihf

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

cargo doc --features mctp-estack/log

echo success
