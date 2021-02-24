# Benchmarking

To run:

```bash
cargo bench
```

This library uses [Criterion](https://github.com/bheisler/criterion.rs) for benchmarks. 
After running the bench command the report can be viewed at [`target/criterion/report/index.html`](../target/criterion/report/index.html).

Note there will be significant differences when you choose different security levels or 90's mode.

Current benches: 

* Keypair generation
* Encapsulation of a public key
* Correct Decapsulation of a ciphertext
* Decapsulation failure of a ciphertext
