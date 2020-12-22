#!/bin/env bash
set -e

# kyber764
cargo test --features "KATs"
cargo test --features "KATs 90s"

cargo test --features "KATs kyber512"
cargo test --features "KATs kyber512 90s"

cargo test --features "KATs kyber1024"
cargo test --features "KATs kyber1024 90s"

