# Known Answer Tests

Repo: https://github.com/pq-crystals/kyber

### Generate files
``` shell
git clone https://github.com/pq-crystals/kyber.git
cd kyber/ref
make
./PQCgenKAT_kem
```

Change `KYBER_K` in `params.h` to both 2 and 4 for the alternate security levels, compile with `make` and run again.


For the 90s version KATs uncomment `#define KYBER_90S` in the parameters and repeat the procedure above. You'll need to rename these files as they are produced with the equivalent names.
