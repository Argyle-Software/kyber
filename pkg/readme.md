# KYBER

<p align="center">
  <img src="https://raw.githubusercontent.com/Argyle-Software/kyber/master/kyber.png"/>
</p>

A rust implementation of the post-quantum key exchange algorithm Kyber, packaged as a wasm binary.

This version currently uses kyber764, equivalent to a 192 bit security level. To use different variants or enable 90's mode, check the [github instructions](https://github.com/Argyle-Software/kyber#webassembly) for how to compile it yourself.  

### Installation

```shell
npm -i pqc-kyber
```

### Usage

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
assert.equal(ciphertextBob.len(),  kyber.Params.ciphertextBytes);
assert.equal(sharedSecretAlice.len(), kyber.Params.sharedSecretBytes)

```


### Errors

Will be raised if:


 * The ciphertext cannot be decapsulated with the private key 
 * Functions are given incorrectly sized byte arrays 

Valid input sizes are all contained in the `kyber.Params` class.

### Security Considerations

Kyber is relatively new, it is highly advised to use it in a hybrid key exchange system, alongside a traditional algorithm like X25519 rather than by itself.

For further reading the IETF have a draft construction for hybrid key exchange in TLS 1.3:

https://www.ietf.org/archive/id/draft-ietf-tls-hybrid-design-04.html


### About

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
