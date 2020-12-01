# Kyber

<p align="center">
  <img src="https://pq-crystals.org/kyber/src/kyber.png"/>
</p>

----

[![Build Status](https://travis-ci.com/mitchellberry/kyber.svg?branch=master)](https://travis-ci.com/mitchellberry/kyber)
[![Coverage Status](https://coveralls.io/repos/github/mitchellberry/kyber/badge.svg?branch=develop)](https://coveralls.io/github/mitchellberry/kyber?branch=develop)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](https://github.com/mitchellberry/kyber/blob/master/LICENSE)
[![NPM](https://img.shields.io/npm/v/pqc-kyber)](https://www.npmjs.com/package/pqc-kyber)
[![Crates](https://img.shields.io/crates/v/pqc-kyber)](https://crates.io/crates/pqc-kyber)
[![Docs](https://docs.rs/pqc-kyber/badge.svg)](https://docs.rs/pqc-kyber)

A pure rust implementation of Kyber that compiles to Wasm. This is a translation of the third round optimized submission written in C. Modifications may still occur in the near future. Please use at your own risk and read the [security considerations](#Security_Considerations) section. 

---

### About

Kyber is an IND-CCA2-secure key encapsulation mechanism (KEM), whose security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices. Kyber is one of the candidate algorithms submitted to the [NIST post-quantum cryptography project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography). The submission lists three different parameter sets aiming at different security levels. Specifically, Kyber-512 aims at security roughly equivalent to AES-128, Kyber-768 aims at security roughly equivalent to AES-192, and Kyber-1024 aims at security roughly equivalent to AES-256. 

---

### Installation

In `cargo.toml`:

```toml
[dependencies]
pqc-kyber = 0.1.0
```

### Usage

```rust
use pqc_kyber::*;
```

#### KEM

```rust
// Generate Keypair
let keys = keypair();

// Encapsulate
let (ct, ss1) = encapsulate(&keys.pubkey).unwrap();

// Decapsulate
let ss2 = decapsulate(&ct, &keys.secret).unwrap();
```

#### Key Exchange
```rust
// Initialise
let mut eska = [0u8; KYBER_SECRETKEYBYTES];

let mut uake_senda = [0u8; KEX_UAKE_SENDABYTES];
let mut uake_sendb = [0u8; KEX_UAKE_SENDBBYTES];

let mut tk = [0u8; KEX_SSBYTES];
let mut ka = [0u8; KEX_SSBYTES];
let mut kb = [0u8; KEX_SSBYTES];

let alice_keys = keypair();
let bob_keys = keypair();
```

##### Unilaterally Authenticated Key Exchange
```rust
// Alice
uake_init_a(
 &mut uake_senda, 
 &mut tk, 
 &mut eska, 
 &bob_keys.pubkey
);
// Bob
uake_shared_b(
 &mut uake_sendb, 
 &mut kb, 
 &uake_senda, 
 &bob_keys.secret
).unwrap();
// Alice
uake_shared_a(
 &mut ka, 
 &uake_sendb, 
 &tk, 
 &eska
).unwrap();

assert_eq!(ka, kb);
```

##### Mutually Authenticated Key Exchange
```rust
 // Alice
 ake_init_a(
   &mut ake_senda, 
   &mut tk, 
   &mut eska, 
   &bob_keys.pubkey
 );
 // Bob
 ake_shared_b(
   &mut ake_sendb, 
   &mut kb, 
   &ake_senda, 
   &bob_keys.secret,
   &alice_keys.pubkey
 ).unwrap();
 // Alice
 ake_shared_a(
   &mut ka, 
   &ake_sendb, 
   &tk, 
   &eska,
   &alice_keys.secret
 ).unwrap();

 assert_eq!(ka, kb);
```

---


### Testing

Key exchange and decapsulation can be tested as normal but for the keypairs and encapsulation requiring deterministic rng seeds you'll need to enable to the KATs feature

```
cargo test --features KATs
```

---

### Benchmarking

Uses criterion for benchmarking the KEM functions. If you have GNU Plot installed it will generate graphs in `target/criterion/`. Please check the benchmarks for regressions if you intend to submit a PR.

```
cargo bench
```

---

### WebAssembly

This library compiled to Wasm is published on npm.

https://www.npmjs.com/package/pqc-kyber

To install:

```
npm i pqc-kyber
```

See also the basic html demo in the examples that can be run and inspected.

To compile you'll need `wasm-pack`, and either `wasm32-unknown-unknown` or `wasm32-unknown-escripten` targets installed for your toolchain. Also requires the wasm feature enabled.

```
wasm-pack build -- --features wasm
```

---

### Contributing 

Contributions welcome. Create a feature fork and submit a PR to the development branch. Please run the benchmarking to check for any regressions first.

### Security Considerations

The NIST post quantum standardisation project is still ongoing and this algorithm is quite new.

While care has been taken porting from the C reference codebase, this library has not undergone any security auditing nor can any guarantees be made about the potential for underlying vulnerabilities or potential side-channel attacks.

Please use at your own risk.
