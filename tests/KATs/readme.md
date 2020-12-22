# Known Answer Tests

The test vectors need to be generated locally. The instructions below clone the C reference repo, compile the test binaries, generates and renames the vectors.

This results in 6 files each containing 10000 KATs, total size is ~600MB:

* tvecs512
* tvecs512-90s
* tvecs768
* tvecs768-90s
* tvecs1024
* tvecs1024-90s

These need to be then moved into the `$CARGO_ROOT/tests/KATs` folder to run the tests.


C Reference Repo: https://github.com/pq-crystals/kyber


## Generating test vectors

```bash
git clone https://github.com/pq-crystals/kyber.git;
cd kyber/ref;
make;

# Create vectors for each security level and mode
for tvec in test_vectors*[^.c];
  do
  sub_str=${tvec/est_/};
  ./$tvec > ${sub_str/tor/};
done;

# SHA256SUMS
for tvec in tvecs{5,7,1}*;
  do
  sha256sum $tvec >> SHA256SUMS;
done;

# Move test vectors and sha256sums into the PQC-Kyber KATs folder
mv {tvecs*,SHA256SUMS} <Project Root>/tests/KATs

# Confirm SHA256SUMS match rust repo
# Please raise an issue if upstream tests vectors have changed
diff SHA256SUMS_ORIG SHA256SUMS
```