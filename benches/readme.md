# Benchmarking

This library uses Criterion for benchmarks. 

The current benches: 

* Keypair generation
* Encapsulation of a single public key
* Correct Decapsulation of a single ciphertext
* Decapsulation failure of a single ciphertext

### Contributers

For anyone interested in helping out

1. Run the *system_printout* script to provide details
2. Delete any previous criterion folder, from the crate root: `rm -r target/criterion`
3. Benchmark with `cargo bench`
