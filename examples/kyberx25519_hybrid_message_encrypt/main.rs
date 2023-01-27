// Using a hybrid kyberx25519 key exchange to derive a shared secret, 
// from which a message is encrypted and transmitted to another party.
// Enable the [dev-deps] feature to run this: 
// cargo run --example hybrid_encrypt_message --features dev-deps

use pqc_kyber::{encapsulate, decapsulate};
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use ed25519_compact::x25519;
use aes_gcm::{
  aead::{Aead, KeyInit, OsRng},
  Aes256Gcm, Nonce
};

fn main() {  
  let msg = b"hello"; // Very important message
  
  /////////////////////
  // Associated Data //
  /////////////////////

  let nonce = Nonce::from_slice(b"unique nonce"); // Even better is 12 bytes from OsRng
  let salt = Some(b"bob@salt.com".as_slice());    // Optional, please do though
  let context = b"kyber_x25519_hybrid_demo";      // Domain separation

  //////////
  // Keys //
  //////////

  // Bob's kyber keys
  let keys_bob_kyber = pqc_kyber::keypair(&mut OsRng);
  let keys_bob_kyber_public = keys_bob_kyber.public;

  // Alice and Bob's x25519 keys
  let keys_alice_x25519 = x25519::KeyPair::generate();
  let keys_bob_x25519 = x25519::KeyPair::generate();
  let keys_alice_x25519_public = keys_alice_x25519.pk;
  let keys_bob_x25519_public = keys_bob_x25519.pk;

  ///////////
  // Alice //
  ///////////
  
  // Get kyber shared secret and ciphertext from Bob's kyber public key
  let (kyber_ct, kyber_shared_secret_alice) = encapsulate(&keys_bob_kyber_public, &mut OsRng).unwrap();
  
  // Derive the x25519 shared secret -
  let mut x25519_shared_secret_alice = [0u8; 32];
  let x25519_dh_alice = keys_bob_x25519_public.dh(&keys_alice_x25519.sk).unwrap();
  let kdf_alice = Hkdf::<Sha256>::new(salt, x25519_dh_alice.as_slice());
  kdf_alice.expand(context.as_slice(), &mut x25519_shared_secret_alice).unwrap();

  // Hash both shared secrets to get the hybrid encryption key
  let mut hasher_alice = Sha256::new();
  hasher_alice.update(kyber_shared_secret_alice);
  hasher_alice.update(x25519_shared_secret_alice);
  let hybrid_shared_secret_alice = hasher_alice.finalize();

  // Alice encrypts the message
  let alice_cipher = Aes256Gcm::new(&hybrid_shared_secret_alice.into());
  let encrypted_msg = alice_cipher.encrypt(nonce, msg.as_ref()).unwrap();

  ////////////////////////////////
  /////// Over the wire //////////
  ////////////////////////////////
  // Send to Bob:               //
  // - nonce                    //
  // - salt                     //
  // - context                  //
  // - kyber_ct                 //
  // - keys_alice_x25519_public //
  // - encrypted_msg            //
  ////////////////////////////////

  /////////
  // Bob //
  /////////
  
  // Decapsulate kyber shared secret
  let kyber_shared_secret_bob = decapsulate(&kyber_ct, &keys_bob_kyber.secret).unwrap();
  
  // x25519 shared secret
  let x25519_dh_bob = keys_alice_x25519_public.dh(&keys_bob_x25519.sk).unwrap();
  let kdf_bob = Hkdf::<Sha256>::new(salt, x25519_dh_bob.as_slice());
  let mut x25519_shared_secret_bob = [0u8; 32];
  kdf_bob.expand(context.as_slice(), &mut x25519_shared_secret_bob).unwrap();

  // Hash both shared secrets
  let mut hasher_bob = Sha256::new();
  hasher_bob.update(kyber_shared_secret_bob);
  hasher_bob.update(x25519_shared_secret_bob);
  let hybrid_shared_secret_bob = hasher_bob.finalize();
  
  // Bob decrypts the message
  let bob_cipher = Aes256Gcm::new(&hybrid_shared_secret_bob.into());
  let decrypted_msg = bob_cipher.decrypt(nonce, encrypted_msg.as_ref()).unwrap();

  assert_eq!(kyber_shared_secret_alice, kyber_shared_secret_bob);
  assert_eq!(x25519_shared_secret_alice, x25519_shared_secret_bob);
  assert_eq!(msg, &decrypted_msg.as_ref());
}