#!/bin/env bash
set -e

# Tests intended to be run on x86_64
# avx2 90s mode not yet implemented

cargo test --features "KATs" # kyber764
# cargo test --features "KATs 90s" # kyber764

cargo test --features "KATs kyber512"
# cargo test --features "KATs kyber512 90s"

cargo test --features "KATs kyber1024"
# cargo test --features "KATs kyber1024 90s"

cargo test --features "reference KATs"
cargo test --features "reference KATs 90s"

cargo test --features "reference KATs kyber512"
cargo test --features "reference KATs kyber512 90s"

cargo test --features "reference KATs kyber1024"
cargo test --features "reference KATs kyber1024 90s"


