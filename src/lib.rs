#![allow(clippy::many_single_char_names)]

// mod aes256;
mod api;
mod cbd;
mod error;
mod fips202;
mod indcpa;
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

use error::KyberError;
#[cfg(feature="verify-KATs")]
pub use api::{crypto_kem_keypair, crypto_kem_enc, crypto_kem_dec};
pub use params::{KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_CIPHERTEXTBYTES, KYBER_SSBYTES};

pub fn keypair() -> Result<([u8; KYBER_PUBLICKEYBYTES], [u8; KYBER_SECRETKEYBYTES]), KyberError> {
  let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
  let mut sk = [0u8; KYBER_SECRETKEYBYTES];
  api::crypto_kem_keypair(&mut pk, &mut sk, None);
  Ok((pk, sk))  
}

pub fn encode(pk: &[u8]) -> Result<([u8; KYBER_CIPHERTEXTBYTES], [u8; KYBER_SSBYTES]), KyberError> {
  if pk.len() != KYBER_PUBLICKEYBYTES {
    return Err(KyberError::EncodeFail)
  }
  let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
  let mut ss = [0u8; KYBER_SSBYTES];
  api::crypto_kem_enc(&mut ct, &mut ss, pk, None);
  Ok((ct, ss))
}


pub fn decode<'a>(ss: &'a mut [u8], ct: &[u8], sk: &[u8]) -> Result<&'a[u8], KyberError> {
  match api::crypto_kem_dec(ss, ct, sk) {
    Ok(_) => Ok(ss),
    Err(e) => Err(e)
  }
}