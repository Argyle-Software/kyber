

<p align="center">
  <img src="./kyber.png"/>
</p>

----

# Kyber

[![Build Status](https://travis-ci.com/Argyle-Cybersystems/kyber.svg?branch=master)](https://travis-ci.com/Argyle-Cybersystems/kyber)
[![Coverage Status](https://coveralls.io/repos/github/Argyle-Cybersystems/kyber/badge.svg?branch=develop)](https://coveralls.io/github/Argyle-Cybersystems/kyber?branch=develop)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](https://github.com/Argyle-Cybersystems/kyber/blob/master/LICENSE)
[![NPM](https://img.shields.io/npm/v/pqc-kyber)](https://www.npmjs.com/package/pqc-kyber)
[![Crates](https://img.shields.io/crates/v/pqc-kyber)](https://crates.io/crates/pqc-kyber)
[![Docs](https://docs.rs/pqc-kyber/badge.svg)](https://docs.rs/pqc-kyber)

A no_std rust implementation of Kyber that compiles to WASM, it is based on the reference repo written in C which is still being tweaked, there is likely to be some further modifications to the API. Please read the [security considerations](#Security_Considerations) section before using. 

---

### About

Kyber is an IND-CCA2-secure key encapsulation mechanism (KEM), whose security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices. Kyber is one of the round 3 finalist algorithms submitted to the [NIST post-quantum cryptography project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography). The submission lists three different parameter sets aiming at different security levels. Specifically, Kyber-512 aims at security roughly equivalent to AES-128, Kyber-768 aims at security roughly equivalent to AES-192, and Kyber-1024 aims at security roughly equivalent to AES-256. 

---

### Installation

In `cargo.toml`:

```toml
[dependencies]
pqc-kyber = 0.1.0
```

### Usage

Kyber re-exports `rand:thread_rng()`. For embedded devices and testing purposes this can be disabled with the feature flag `byo-rng`. 

```rust
use pqc_kyber::*;

let mut rng = thread_rng();
```

#### KEM

```rust
// Generate Keypair
let keys = keypair(&mut rng);

// Encapsulate
let (ct, ss1) = encapsulate(&mut rng, &keys.public).unwrap();

// Decapsulate
let ss2 = decapsulate(&mut rng, &ct, &keys.secret).unwrap();
```


/////////////// FIX THIS

#### Key Exchange
```rust
// Initialise
let mut eska = [0u8; KYBER_SECRETKEYBYTES];

let mut uake_senda = [0u8; KEX_UAKE_SENDABYTES];
let mut uake_sendb = [0u8; KEX_UAKE_SENDBBYTES];

let mut tk = [0u8; KEX_SSBYTES];
let mut ka = [0u8; KEX_SSBYTES];
let mut kb = [0u8; KEX_SSBYTES];

let alice_keys = keypair(&mut rng);
let bob_keys = keypair(&mut rng);
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

### Features

TODO: Markdown Table of features


### Testing

The [run_all_tests](tests/run_all_tests.sh) script will traverse all codepaths by running a matrix of all security levels and variants.

Known Answer Tests require deterministic rng seeds, enable the `KATs` feature to run them. Do not use this feature outside of testing, as it exposes private API functions.

```shell
# Runs all KATs for kyber764
cargo test --features "KATs"
```

Please view the [testing readme](./tests/readme.md) for more comphrensive info.

---

### Benchmarking

Uses criterion for benchmarking. If you have GNUPlot installed it will generate statistical graphs in `target/criterion/`.

See the [benchmarking readme](./benches/readme.md)

```
cargo bench
```

---

### WebAssembly

This library has been compiled into a WASM binary package. Usage instructions are published on npm:

https://www.npmjs.com/package/pqc-kyber

Which is also located in the [wasm pkg folder readme](./pkg/README.md)

To install:

```
npm i pqc-kyber
```

See also the basic html demo in the examples that can be run and inspected.

To use this lib for web assembly purposes you'll need the `wasm` feature enabled.

```toml
[dependencies]
pqc-kyber = {version = "0.2.0", features = ["wasm"]
```

Along with `wasm-pack` and `wasm32-unknown-unknown` or `wasm32-unknown-emscripten` target installed for your toolchain.

To build:

```
wasm-pack build -- --features wasm
```



---

### Contributing 

Contributions welcome. For PR's create a feature fork and submit it to the development branch.

### Security Considerations

The NIST post quantum standardisation project is still ongoing 

While care has been taken porting from the C reference codebase, this library has not undergone any security auditing nor can any guarantees be made about the potential for underlying vulnerabilities or potential side-channel attacks.

Please use at your own risk.
