<div align="center">

  <h1>Web Assembly Demo</h1>

  <strong>A basic example of using the pqc_kyber npm module</strong> 



</div>


### Installation

From this folder: 

```shell
npm install
```

### Run
```
npm run start
```

The demo is at [localhost:8080](localhost:8080)


### Library Usage

```js
import * as kyber from "pqc_kyber";

// Generate Keypair
let keys = kyber.keypair();
const publicKeyAlice = keys.pubkey;
const privateKeyAlice = keys.secret;

// Encapsulate secret
try {
    let encapsulated = kyber.encapsulate(publicKeyAlice);
    var ciphertextBob = encapsulated.ciphertext;
    var sharedSecretBob = encapsulated.sharedSecret;
}
catch(err) {
    alert("Error Encapsulating");
}

// Decapsulate secret
try {
    let decapsulated = kyber.decapsulate(ciphertextBob, privateKeyAlice);
    var sharedSecretAlice = decapsulated.sharedSecret
}
catch(err) {
    alert("Error Decapsulating");
}

var assert = require('assert');

assert.equal(sharedSecretAlice, sharedSecretBob)

// Valid input lengths are found in the `Params` class
assert.equal(publicKeyAlice.len(), kyber.Params.publicKeyBytes);
assert.equal(secretKeyAlice.len(), kyber.Params.secretKeyBytes);
assert.equal(ciphertextBob.len(),  kyber.Params.ciphertextbytes);

```


# Errors
If the ciphertext cannot be decapsulated with the private key or the functions are 
given incorrectly sized byte arrays an error will be raised 








