# Benchmarking

On x86_64 platforms using optimised code include the following target features in RUSTFLAGS:

```bash
RUSTFLAGS="-C target-cpu=native -C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt" cargo bench
```


This library uses [Criterion](https://github.com/bheisler/criterion.rs) for benchmarks. 
After running the bench command the report can be viewed at [`target/criterion/report/index.html`](../target/criterion/report/index.html).

Note there will be significant differences when you choose different security levels or 90's mode.

Current benches: 

* Keypair generation
* Encapsulation of a public key
* Correct Decapsulation of a ciphertext
* Decapsulation failure of a ciphertext
