# Kyber

<p align="center">
  <img src="https://pq-crystals.org/kyber/src/kyber.png"/>
</p>

----

[![Build Status](https://travis-ci.com/mitchellberry/kyber.svg?branch=master)](https://travis-ci.com/mitchellberry/kyber)
[![Coverage Status](https://coveralls.io/repos/github/mitchellberry/kyber/badge.svg?branch=develop)](https://coveralls.io/github/mitchellberry/kyber?branch=develop)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/mitchellberry/kyber/blob/master/LICENSE)


A pure rust implementation of Kyber that can compile to WASM. 



### About

Kyber is an IND-CCA2-secure key encapsulation mechanism (KEM), whose security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices. Kyber is one of the candidate algorithms submitted to the [NIST post-quantum cryptography project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography). The submission lists three different parameter sets aiming at different security levels. Specifically, Kyber-512 aims at security roughly equivalent to AES-128, Kyber-768 aims at security roughly equivalent to AES-192, and Kyber-1024 aims at security roughly equivalent to AES-256. 

### Usage


### Testing

### Benchmarking

### WASM Development

You'll need `wasm-pack`, `NPM` and the `wasm32-unknown-unknown` target installed for your toolchain.

To build: 

```
wasm-pack build -- --features wasm
```






### Contributing 

Contributions welcome. Create a feature fork and submit a PR to the development branch. 

### Security Considerations
