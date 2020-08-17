#![allow(clippy::many_single_char_names)]

//! # Kyber
//! 
//! A pure rust implementation of the Kyber algorithm that compiles to wasm.
//! 
//! To select different security strengths from the default enable 
//! in your `cargo.toml` the feature of `kyber512` or `kyber1024` 
//! 
//! ## Usage 
//!
//! ```
//! use pqc_kyber::*;
//! ```
//! ##### KEM
//! ```
//! // Generate Keypair
//! let keys = keypair();
//! 
//! // Encapsulate
//! let (ct, ss1) = encapsulate(&keys.pubkey).unwrap();
//! 
//! // Decapsulate
//! let ss2 = decapsulate(&ct, &keys.secret).unwrap();
//! ```
//! 
//! ##### Key Exchange
//! 
//! ```
//! // Initialise
//!let mut eska = [0u8; KYBER_SECRETKEYBYTES];
//!
//!let mut uake_senda = [0u8; KEX_UAKE_SENDABYTES];
//!let mut uake_sendb = [0u8; KEX_UAKE_SENDBBYTES];
//!
//!let mut tk = [0u8; KEX_SSBYTES];
//!let mut ka = [0u8; KEX_SSBYTES];
//!let mut kb = [0u8; KEX_SSBYTES];
//!
//!let alice_keys = keypair();
//!let bob_keys = keypair();
//! ```
//! 
//! ##### UAKE
//! ```
//!// Alice
//!uake_init_a(
//!  &mut uake_senda, 
//!  &mut tk, 
//!  &mut eska, 
//!  &bob_keys.pubkey
//!);
//!// Bob
//!uake_shared_b(
//!  &mut uake_sendb, 
//!  &mut kb, 
//!  &uake_senda, 
//!  &bob_keys.secret
//!).unwrap();
//!// Alice
//!uake_shared_a(
//!  &mut ka, 
//!  &uake_sendb, 
//!  &tk, 
//!  &eska
//!).unwrap();
//!
//!assert_eq!(ka, kb);
//!```
//! 
//! ##### AKE
//! ```
//!  // Alice
//!  ake_init_a(
//!    &mut ake_senda, 
//!    &mut tk, 
//!    &mut eska, 
//!    &bob_keys.pubkey
//!  );
//!  // Bob
//!  ake_shared_b(
//!    &mut ake_sendb, 
//!    &mut kb, 
//!    &ake_senda, 
//!    &bob_keys.secret,
//!    &alice_keys.pubkey
//!  ).unwrap();
//!  // Alice
//!  ake_shared_a(
//!    &mut ka, 
//!    &ake_sendb, 
//!    &tk, 
//!    &eska,
//!    &alice_keys.secret
//!  ).unwrap();
//!
//!  assert_eq!(ka, kb);
//! ```

#[cfg(feature = "wasm")]
mod wasm;
// mod aes256;
mod api;
mod cbd;
mod error;
mod fips202;
mod indcpa;
mod kex;
mod params;
mod poly;
mod polyvec;
mod ntt;
mod reduce;
mod rng;
mod sha;
mod symmetric;
mod verify;
pub mod utils;

#[cfg(feature="KATs")]
pub use api::{
  crypto_kem_keypair, 
  crypto_kem_enc, 
  crypto_kem_dec
};
pub use kex::*;
pub use error::KyberError;
pub use params::{
  KYBER_PUBLICKEYBYTES, 
  KYBER_SECRETKEYBYTES, 
  KYBER_CIPHERTEXTBYTES, 
  KYBER_SSBYTES, 
  KYBER_K, 
  KYBER_90S
};

/// Generates a new public/private keypair
/// 
/// ### Example
/// ```
/// use kyber::*;
/// 
/// let keys = keypair();
/// let publickey = keys.pubkey;
/// let secretkey = keys.secret;
/// dbg!(utils::encode_hex(&publickey));
/// dbg!(utils::encode_hex(&secretkey));
/// assert_eq!(publickey.len(), KYBER_PUBLICKEYBYTES);
/// assert_eq!(secretkey.len(), KYBER_SECRETKEYBYTES);
/// ```
pub fn keypair() -> Keys {
  let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
  let mut sk = [0u8; KYBER_SECRETKEYBYTES];
  api::crypto_kem_keypair(&mut pk, &mut sk, None);
  Keys {
    pubkey: pk,
    secret: sk,
    ..Default::default()
  } 
}

/// Encapsulates a public key
///
///
/// ### Example
/// ```
/// use kyber::*;
/// 
/// let keys = keypair();
/// let (ct, ss) = encapsulate(&keys.pubkey).unwrap();
/// ```
pub fn encapsulate(pk: &[u8]) -> Result<([u8; KYBER_CIPHERTEXTBYTES], [u8; KYBER_SSBYTES]), KyberError> {
  if pk.len() != KYBER_PUBLICKEYBYTES {
    return Err(KyberError::EncodeFail)
  }
  let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
  let mut ss = [0u8; KYBER_SSBYTES];
  api::crypto_kem_enc(&mut ct, &mut ss, pk, None);
  Ok((ct, ss))
}

/// Decapsulates ciphertext with a secret key
///
/// ### Example
/// ```
/// use kyber::*;
/// 
/// let keys = keypair();
/// let (ct, ss1) = encapsulate(&keys.pubkey).unwrap();
/// let ss2 = decapsulate(&ct, &keys.secret).unwrap();
/// assert_eq!(ss1, ss2);
/// ```
pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Result<[u8; KYBER_SSBYTES], KyberError> {
  let mut ss = [0u8; KYBER_SSBYTES];
  match api::crypto_kem_dec(&mut ss, ct, sk) {
    Ok(_) => Ok(ss),
    Err(e) => Err(e)
  }
}

/// Contains the public/private keypair
#[derive(Copy, Clone)]
pub struct Keys{
    pub pubkey: [u8; KYBER_PUBLICKEYBYTES],
    pub secret: [u8; KYBER_SECRETKEYBYTES]
}

impl Default for Keys {
  fn default() -> Self {
    Keys {
      pubkey: [0u8; KYBER_PUBLICKEYBYTES],
      secret: [0u8; KYBER_SECRETKEYBYTES]
    }
  }
}

