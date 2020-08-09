# Randbuf Generation

This program generates the deterministic random output used in the intermediate stages of both keypair generation and encoding from the KAT seed values. 

`rng.c` and `rng.h` are directly from the NIST submission and `generate_bufs.c` is loosely based off `PQCgenKAT_kem.c` to print out the values from `randombytes()` into their respective files. 

These values are then used in place of regular rng output when running the KATs.


### Usage

To build and run: 

```shell
cd tests/rand_bufs
make
./generate
```

### Original Files

* [rng.c](https://github.com/pq-crystals/kyber/blob/master/ref/rng.c)
* [rng.h](https://github.com/pq-crystals/kyber/blob/master/ref/rng.h)
* [PQCgenKAT_kem.c](https://github.com/pq-crystals/kyber/blob/master/ref/PQCgenKAT_kem.c)


