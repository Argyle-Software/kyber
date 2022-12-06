# Testing

Without any feature flags `cargo test` will run through the key exchange functions and some doctests for the selected security level and mode. Running the Known Answer Tests require deterministic rng buffers from the test vector files. These files are quite large, you will need to generate them yourself. Instructions for building the KAT files are [here](./KAT/readme.md). Otherwise you can run:

```shell
cd KAT
./build_kats.sh
```

Which will clone the C reference repo, generate the KAT files, then rename and put them in the correct folder for testing.

To run the known answer tests you will need to enable `kyber_kat` in `RUSTFLAGS`. To check different Kyber levels or 90's mode you will need to include those flags also. eg:
```bash
RUSTFLAGS=' --cfg kyber-kat' cargo test --features "kyber1024 90s"
```

For applicible x86 architectures you must export the avx2 RUSTFLAGS if you don't want to test on the reference codebase.

To run a matrix of all possible features use the helper script from this folder:
```shell
./run_all_tests.sh
```

The script also checks for the existence of different environment variables and modifies
its behaviour

* KAT: Runs the known answer tests
* AVX2: Runs avx2 code on x86 platforms with compiled GAS files
* NASM: Runs avx2 code with both GAS and NASM files seperately, requires a NASM compiler installed

To activate, instantiate the variables, for example:

```shell
KAT=1 AVX2=1 NASM=1 ./run_all_tests.sh 
```

Test files:

* [kat.rs](./kat.rs)  - Runs a battery of test vectors using the Known Answer Test file of the selected security level and mode. There are 10,000 KATs per file.

* [kex.rs](./kex.rs) - Goes through a full key exchange procedure for both the UAKE and AKE functions.

* [kem.rs](./kem.rs) - A single run of random key generation, encapsulation and decapsulation.
