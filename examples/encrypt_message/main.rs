use pqc_kyber::*;
use aes_gcm::{
  aead::{Aead, KeyInit, OsRng},
  Aes256Gcm, Nonce
};

// Derives a shared secret then uses that to encrypt a message for transmission

fn main() {
  let msg = b"hello";
  dbg!(&msg);
  let nonce = Nonce::from_slice(b"unique nonce"); // 12 bytes
  let keys_bob = keypair(&mut OsRng);

  // Alice
  let (kem_ct, shared_secret_alice) = encapsulate(&keys_bob.public, &mut OsRng).unwrap();
  let alice_cipher = Aes256Gcm::new(&shared_secret_alice.into());
  let encrypted_msg = alice_cipher.encrypt(nonce, msg.as_ref()).unwrap();

  // Send nonce, kem_ct and encrypted_msg to Bob

  // Bob
  let shared_secret_bob = decapsulate(&kem_ct, &keys_bob.secret).unwrap();
  let bob_cipher = Aes256Gcm::new(&shared_secret_bob.into());
  let decrypted_msg = bob_cipher.decrypt(nonce, encrypted_msg.as_ref()).unwrap();
  assert_eq!(msg, &decrypted_msg.as_ref());
  dbg!(decrypted_msg);
}