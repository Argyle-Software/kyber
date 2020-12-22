# Testing

Without any feature flags `cargo test` will run through the key exchange functions and decapsulation known answer tests for the selected security level and mode. Keypair generation and encapsulation require deterministic rng buffers from test vector files. These files are too large for git and you will need to generate them yourself from the C reference repo. Instructions for this are [here](./KATs/readme.md)

To run all the tests you will need to use the *KATs* feature flag. To check different Kyber levels or 90's mode you will need to include those flags also. eg:
```bash
cargo test --features "KATs kyber1024 90s"
```

To run all possible tests there is a helper script in this folder:
```bash
./run_all_tests.sh
```

Test files:

* *[kat.rs](./kat.rs)*  - Runs a test suite using KAT files at the selected security level

* *[kex.rs](./kex.rs)* - Goes through a full key exchange procedure for both the UAKE and AKE functions.

* *[kyber.rs](./kyber.rs)* - Generates 1000 different keys and encapsulates/decapsulates them using the higher level Kyber struct functions.



