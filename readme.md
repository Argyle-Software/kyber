

<p align="center">
  <img src="./kyber.png"/>
</p>


# Kyber
[![Build Status](https://github.com/Argyle-Software/kyber/actions/workflows/kat.yml/badge.svg)](https://github.com/Argyle-Software/kyber/actions)
[![Crates](https://img.shields.io/crates/v/pqc-kyber)](https://crates.io/crates/pqc-kyber)
[![NPM](https://img.shields.io/npm/v/pqc-kyber)](https://www.npmjs.com/package/pqc-kyber)
[![License](https://img.shields.io/crates/l/pqc_kyber)](https://github.com/Argyle-Software/kyber/blob/master/LICENSE-MIT)

A rust implementation of the Kyber algorithm, a KEM standardised by the NIST Post-Quantum Standardization Project.

This library:
* Is no_std compatible and needs no allocator, suitable for embedded devices. 
* Reference files contain no unsafe code and are written in pure rust.
* On x86_64 platforms offers an avx2 optimized version, which includes assembly from the C reference repo. 
* Compiles to WASM using wasm-bindgen and has a ready-to-use binary published on NPM.


See the [**features**](#features) section for different options regarding security levels and modes of operation. The default security setting is kyber768.

It is recommended to use Kyber in a hybrid system alongside a traditional key exchange algorithm such as X25519. 

Please also read the [**security considerations**](#security-considerations) before use.

**Minimum Supported Rust Version: 1.47.0**

---

## Installation

```shell
cargo add pqc_kyber
```

or 

```toml
pqc_kyber = "0.4.0"

## Usage 

```rust
use pqc_kyber::*;
```

For optimisations on x86 platforms enable the `avx2` feature and the following RUSTFLAGS:

```shell
export RUSTFLAGS="-C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt"
```

---

### Key Encapsulation

```rust
// Generate Keypair
let keys_bob = keypair(&mut rng);

// Alice encapsulates a shared secret using Bob's public key
let (ciphertext, shared_secret_alice) = encapsulate(&keys_bob.public, &mut rng)?;

// Bob decapsulates a shared secret using the ciphertext sent by Alice 
let shared_secret_bob = decapsulate(&ciphertext, &keys_bob.secret)?;

assert_eq!(shared_secret_alice, shared_secret_bob);
```

---

### Unilaterally Authenticated Key Exchange
```rust
let mut rng = rand::thread_rng();

// Initialize the key exchange structs
let mut alice = Uake::new();
let mut bob = Uake::new();

// Generate Bob's Keypair
let bob_keys = keypair(&mut rng);

// Alice initiates key exchange
let client_init = alice.client_init(&bob_keys.public, &mut rng);

// Bob authenticates and responds
let server_response = bob.server_receive(
  client_init, &bob_keys.secret, &mut rng
)?;

// Alice decapsulates the shared secret
alice.client_confirm(server_response)?;

// Both key exchange structs now have the same shared secret
assert_eq!(alice.shared_secret, bob.shared_secret);
```

---

### Mutually Authenticated Key Exchange
Follows the same workflow except Bob requires Alice's public keys:

```rust
let mut alice = Ake::new();
let mut bob = Ake::new();

let alice_keys = keypair(&mut rng);
let bob_keys = keypair(&mut rng);

let client_init = alice.client_init(&bob_keys.public, &mut rng);

let server_response = bob.server_receive(
  client_init, &alice_keys.public, &bob_keys.secret, &mut rng
)?;

alice.client_confirm(server_response, &alice_keys.secret)?;

assert_eq!(alice.shared_secret, bob.shared_secret);
```

---

## Errors
The KyberError enum has two variants:

* **InvalidInput** - One or more inputs to a function are incorrectly sized. A possible cause of this is two parties using different security levels while trying to negotiate a key exchange.

* **Decapsulation** - The ciphertext was unable to be authenticated. The shared secret was not decapsulated.

---

## Features

If no security level is specified then kyber768 is used by default as recommended by the authors. It is roughly equivalent to AES-192.  Apart from the two security levels, all other features can be combined as needed. For example:

```toml
[dependencies]
pqc_kyber = {version = "0.4.0", features = ["kyber512", "90s", "avx2"]}
```


| Feature   | Description |
|-----------|------------|
| kyber512  | Enables kyber512 mode, with a security level roughly equivalent to AES-128.|
| kyber1024 | Enables kyber1024 mode, with a security level roughly equivalent to AES-256.  A compile-time error is raised if more than one security level is specified.|
| 90s | Uses SHA2 and AES in counter mode as a replacement for SHAKE. This can provide hardware speedups in some cases. |
| avx2 | On x86_64 platforms enable the optimized version. This flag is will cause a compile error on other architectures. |
| wasm | For compiling to WASM targets|
| nasm | Uses Netwide Assembler avx2 code instead of GAS for portability. Requires a nasm compiler: https://www.nasm.us/ | 
| zeroize | This will zero out the key exchange structs on drop using the [zeroize](https://docs.rs/zeroize/latest/zeroize/) crate |
| std | Enable the standard library |
| benchmarking | Enables the criterion benchmarking suite |
---

## Testing

The [run_all_tests](tests/run_all_tests.sh) script will traverse all possible codepaths by running a matrix of the security levels, variants and crate features.

Known Answer Tests require deterministic rng seeds, enable `kyber_kat` in `RUSTFLAGS`to use them. 
Using this outside of `cargo test` will result in a compile-time error. 
The test vector files are quite large, you will need to build them yourself from the C reference code. 
There's a helper script to do this [here](./tests/KAT/build_kats.sh). 

```bash
# This example runs the basic tests for kyber768
cargo test

# This runs the KATs for kyber512 in 90's mode
RUSTFLAGS='--cfg kyber_kat' cargo test --features "kyber512 90s"
```

See the [testing readme](./tests/readme.md) for more comprehensive info.

---

## Benchmarking

Uses criterion for benchmarking. If you have GNUPlot installed it will generate statistical graphs in `./target/criterion/`.

You will need to enable the `benchmarking` feature.

See the [benchmarking readme](./benches/readme.md) for information on correct usage.

---

## Fuzzing

The fuzzing suite uses honggfuzz, installation and instructions are on the [fuzzing](./fuzz/readme.md) page. 

---

## WebAssembly

This library has been compiled into web assembly and published as a npm package. Usage instructions are here:

https://www.npmjs.com/package/pqc-kyber

Which is also located here in the [wasm readme](./pkg/readme.md)

To install:

```shell
npm i pqc-kyber
```

To compile the wasm files yourself you need to enable the `wasm` feature.

For example, using [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/):

```shell
wasm-pack build -- --features wasm
```

Which will export the wasm, javascript and  typescript files into [./pkg/](./pkg/readme.md). 

To compile a different variant into a separate folder: 
```shell
wasm-pack build --out-dir pkg_kyber512/ -- --features "wasm kyber512" 
```

There is also a basic html demo in the [www](./www/readme.md) folder.
 
From the www folder run: 

```shell
npm run start
```

---

## Security Considerations 

While much care has been taken porting from the C reference codebase, this library has not undergone any third-party security auditing nor can any guarantees be made about the potential for underlying vulnerabilities in LWE cryptography or potential side-channel attacks arising from this implementation.

Kyber is relatively new, it is advised to use it in a hybrid key exchange system alongside a traditional algorithm like X25519 rather than by itself. 

For further reading the IETF have a draft construction for hybrid key exchange in TLS 1.3:

https://www.ietf.org/archive/id/draft-ietf-tls-hybrid-design-04.html

You can also see how such a system is implemented [here](https://github.com/openssh/openssh-portable/blob/a2188579032cf080213a78255373263466cb90cc/kexsntrup761x25519.c) in C by OpenSSH

Please use at your own risk.

---

## About

Kyber is an IND-CCA2-secure key encapsulation mechanism (KEM), whose security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices. It is the final standardised algorithm resulting from the [NIST post-quantum cryptography project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography).

The official website: https://pq-crystals.org/kyber/

Authors of the Kyber Algorithm: 

* Roberto Avanzi, ARM Limited (DE)
* Joppe Bos, NXP Semiconductors (BE)
* Léo Ducas, CWI Amsterdam (NL)
* Eike Kiltz, Ruhr University Bochum (DE)
* Tancrède Lepoint, SRI International (US)
* Vadim Lyubashevsky, IBM Research Zurich (CH)
* John M. Schanck, University of Waterloo (CA)
* Peter Schwabe, Radboud University (NL)
* Gregor Seiler, IBM Research Zurich (CH)
* Damien Stehle, ENS Lyon (FR)

---

### Contributing 

Contributions welcome. For pull requests create a feature fork and submit it to the development branch. More information is available on the [contributing page](./contributing.md)

---

### Alternatives

The PQClean project has rust bindings for their Kyber C codebase:

https://github.com/rustpq/pqcrypto

