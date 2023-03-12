# Contributing

Contributions always welcome. Checkout the development branch create a feature fork and submit a PR back to the development branch. If possible please run a benchmark first for any significant regressions. 

Current areas of focus:

* **Neon ARM intrinsics** - There is a [neon library](https://github.com/cothan/kyber/tree/round3/neon) for Kyber, though currently many ARM intrinsics still don't exist in rust, so there's two branches, `neon` is a rust port of his work that will have to wait until the intrinsics are upstream, `neon_c` is using the original C code with a FFI.
* **Optimizations** - See the benchmarking readme, possibly some fat that can still be trimmed off.
* **Serde** - Implement Serialize/Deserialize traits for the structs and put it behind a feature gate.
* **Mutually Exclusive Features** Currently the crate has all the variants behind feature gates that can't be used together, this is an antipattern in rust, the alternatives are to split the crate up with a lot code of code duplication and maintain them all separately, or make many functions generic, neither are ideal or easy to do.

By submitting any code to this repository you agree to have it licensed under both Apache 2.0 and MIT.  