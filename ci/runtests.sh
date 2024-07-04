#!/bin/bash

set -v
set -e

rustup target add thumbv7em-none-eabihf

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

cargo doc

echo success
