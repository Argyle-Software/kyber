#!/bin/env bash
set -e

# Tests intended to be run on x86_64 platforms

# Enable target features
export RUSTFLAGS="-C target-cpu=native -C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt"

# Print Test Type
announce(){
  title="\n\n#  $1  #\n\n"
  edge=$(echo "$title" | sed 's/./#/g')
  echo "$edge"; echo "$title"; echo "$edge";
}

# Initial compile
cargo build --tests --features "KATs kyber512"

announce "Kyber512"
cargo test  --features "KATs kyber512"

announce "Kyber764"
cargo test  --features "KATs" # kyber764

announce "Kyber1024" 
cargo test  --features "KATs kyber1024"

cargo build --tests --features "KATs kyber512 90s"

announce "Kyber512-90s"
cargo test  --features "KATs kyber512 90s"

announce "Kyber764-90s"
cargo test  --features "KATs 90s" # kyber764-90s

announce "Kyber1024-90s"
cargo test  --features "KATs kyber1024 90s"

announce "Reference Kyber512"
cargo test  --features "reference KATs kyber512"

announce "Reference Kyber764"
cargo test  --features "reference KATs"

announce "Reference Kyber1024"
cargo test  --features "reference KATs kyber1024"

announce "Reference Kyber764-90s"
cargo test  --features "reference KATs 90s"

announce "Reference Kyber512-90s"
cargo test  --features "reference KATs kyber512 90s"

announce "Reference Kyber1024-90s"
cargo test  --features "reference KATs kyber1024 90s"
