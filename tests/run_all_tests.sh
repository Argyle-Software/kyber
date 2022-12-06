#!/bin/bash
set -e

# This script runs a matrix of every valid feature combination
#
# Variables: 
# KAT - Runs the known answer tests
# AVX2 - Runs avx2 code on x86 platforms with compiled GAS files
# NASM - Runs avx2 code with both GAS and NASM files seperately

# Enable avx2 target features
# Enable LLVM address sanitser checks
# export RUSTFLAGS="-Z sanitizer=address -C target-cpu=native -C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt"
# export RUSTDOCFLAGS="-Z sanitizer=address" 

TARGET=$(rustc -vV | sed -n 's|host: ||p')

RUSTFLAGS=${RUSTFLAGS:-""}

# KAT and AVX2 bash variables
if [ -z "$KAT" ]
  then
    echo Not running Known Answer Tests 
  else
  echo Running Known Answer Tests
    RUSTFLAGS+=" --cfg kyber_kat"
fi

if [ -z "$AVX2" ]
  then
    echo Not using AVX2 optimisations 
    OPT=("")
  else
    echo Using AVX2 optimisations with GAS assembler
    OPT=("" "avx2")
fi

if [[ ! -z "$NASM" ]]
  then
    echo Using AVX2 optimisations with NASM assembler
    OPT+=("nasm")
fi

# # Required for address sanitiser checks
# rustup default nightly

# Print Headers
announce(){
  title="#    $1    #"
  edge=$(echo "$title" | sed 's/./#/g')
  echo -e "\n\n$edge"; echo "$title"; echo -e "$edge";
}

##############################################################

start=`date +%s`

announce $TARGET

LEVELS=("kyber512" "kyber768" "kyber1024")
NINES=("" "90s")

for level in "${LEVELS[@]}"; do
  for nine in "${NINES[@]}"; do
    for opt in "${OPT[@]}"; do
      name="$level $nine $opt"
      feat=${level:+"$level"}${opt:+",$opt"}${nine:+",$nine"}
      announce "$name"
      RUSTFLAGS=$RUSTFLAGS cargo test --features $feat
      break;
    done
  done
done

end=`date +%s`
runtime=$((end-start))
announce "Test runtime: $runtime seconds"
