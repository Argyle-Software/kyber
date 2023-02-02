# Benchmarking

On x86_64 platforms using optimised code include the following target features in RUSTFLAGS:

```bash
export RUSTFLAGS="-C target-cpu=native -C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt"
```

This library uses [Criterion](https://github.com/bheisler/criterion.rs) for benchmarks. 
After running the bench command the report can be viewed at [`target/criterion/report/index.html`](../target/criterion/report/index.html).

Note that that keypair generation often bounces around a fair bit even without code changes. 
Don't be surprised to significant speedups and regressions.

You will need to enable the benchmarking feature to run:

```bash
cargo bench --features "benchmarking kyber1024 avx2"
```
This is a workaround for issues with address sanitizer checks in the test suite. 

More details on criterion usage [here](https://bheisler.github.io/criterion.rs/book/user_guide/command_line_options.html)

Current benches: 

* Keypair generation
* Encapsulation
* Correct Decapsulation
* Decapsulation failure
