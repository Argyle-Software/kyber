#!/bin/env bash
set -e

cargo test --features "KATs" # kyber764
cargo test --features "KATs 90s" # kyber764

cargo test --features "KATs kyber512"
cargo test --features "KATs kyber512 90s"

cargo test --features "KATs kyber1024"
cargo test --features "KATs kyber1024 90s"

cargo test --features "avx2 KATs"
# cargo test --features "avx2 KATs 90s"

cargo test --features "avx2 KATs kyber512"
# cargo test --features "avx2 KATs kyber512 90s"

cargo test --features "avx2 KATs kyber1024"
# cargo test --features "avx2 KATs kyber1024 90s"

