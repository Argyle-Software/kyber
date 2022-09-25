#!/bin/bash
set -e

# This script runs a matrix of every valid feature combination

# Enable avx2 target features
# Enable LLVM address sanitser checks
# export RUSTFLAGS="-Z sanitizer=address -C target-cpu=native -C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt"
# export RUSTDOCFLAGS="-Z sanitizer=address" 

TARGET=$(rustc -vV | sed -n 's|host: ||p')

# If any argument supplied run KAT's
if [ -z "$1" ]
  then
    KAT=""
  else
    KAT="KAT"
fi

# # Required for address sanitiser checks
# rustup default nightly

# Print Headers
announce(){
  title="#    $1    #"
  edge=$(echo "$title" | sed 's/./#/g')
  echo -e "\n$edge"; echo "$title"; echo -e "$edge";
}

##############################################################

start=`date +%s`

announce $TARGET

LEVELS=("kyber512", "kyber768", "kyber1024")
OPT=("" "reference")
NINES=("" "90s")

for level in "${LEVELS[@]}"; do
 for opt in "${OPT[@]}"; do
    for nine in "${NINES[@]}"; do
      name="$level $opt $nine"
      feat=${level:+"$level"}${opt:+",$opt"}${nine:+",$nine"}${KAT:+",$KAT"}
      announce "$name"
      cargo test --features  $feat
      break;
    done
  done
done

end=`date +%s`
runtime=$((end-start))
announce "Test runtime: $runtime seconds"
