#![allow(clippy::many_single_char_names)]

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
pub use kex::{
  ake_init_a, 
  ake_shared_a, 
  ake_shared_b, 
  uake_init_a, 
  uake_shared_a, 
  uake_shared_b
};
pub use error::KyberError;
pub use params::{
  KYBER_PUBLICKEYBYTES, 
  KYBER_SECRETKEYBYTES, 
  KYBER_CIPHERTEXTBYTES, 
  KYBER_SSBYTES, 
  KYBER_K, 
  KYBER_90S
};

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

pub fn encapsulate(pk: &[u8]) -> Result<([u8; KYBER_CIPHERTEXTBYTES], [u8; KYBER_SSBYTES]), KyberError> {
  if pk.len() != KYBER_PUBLICKEYBYTES {
    return Err(KyberError::EncodeFail)
  }
  let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
  let mut ss = [0u8; KYBER_SSBYTES];
  api::crypto_kem_enc(&mut ct, &mut ss, pk, None);
  Ok((ct, ss))
}

pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Result<[u8; KYBER_SSBYTES], KyberError> {
  let mut ss = [0u8; KYBER_SSBYTES];
  match api::crypto_kem_dec(&mut ss, ct, sk) {
    Ok(_) => Ok(ss),
    Err(e) => Err(e)
  }
}

#[derive(Copy, Clone)]
pub struct Keys{
    pub pubkey: [u8; KYBER_PUBLICKEYBYTES],
    pub secret: [u8; KYBER_SECRETKEYBYTES],
    pub ciphertext: [u8; KYBER_CIPHERTEXTBYTES],
    pub shared_secret: [u8; KYBER_SSBYTES],
}

impl Default for Keys {
  fn default() -> Self {
    Keys {
      pubkey: [0u8; KYBER_PUBLICKEYBYTES],
      secret: [0u8; KYBER_SECRETKEYBYTES],
      ciphertext: [0u8; KYBER_CIPHERTEXTBYTES],
      shared_secret: [0u8; KYBER_SSBYTES]
    }
  }
}

