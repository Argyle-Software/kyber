use rand_core::{RngCore, CryptoRng};
use crate::{
  KyberError,
  api::*,
  fips202::shake256,
  params::*
};

/// Unlateral key exchange send B size
pub const KEX_UAKE_SENDABYTES: usize = KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES;

/// Unilateral key exchange send B size
pub const KEX_UAKE_SENDBBYTES: usize = KYBER_CIPHERTEXTBYTES;

/// Key exchange send A size
pub const KEX_AKE_SENDABYTES: usize = KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES;

/// Key exchange send B size
pub const KEX_AKE_SENDBBYTES: usize = 2 * KYBER_CIPHERTEXTBYTES;

/// Key exchange shared key size
pub const KEX_SSBYTES: usize = KYBER_SSBYTES;

/// Unilaterally authenticated key exchange initiation
pub fn uake_init_a<R>(
  send: &mut[u8], 
  tk: &mut[u8], 
  sk: &mut[u8], 
  pkb: &[u8],
  rng: &mut R
) -> Result<(), KyberError>
  where R: CryptoRng + RngCore
{
  crypto_kem_keypair(send, sk, rng, None)?;
  crypto_kem_enc(&mut send[KYBER_PUBLICKEYBYTES..], tk, pkb, rng, None)?;
  Ok(())
}

/// Unilaterally authenticated key exchange computation by Bob 
pub fn uake_shared_b<R>(
  send: &mut[u8], 
  k: &mut[u8], 
  recv: &[u8], 
  skb: &[u8],
  rng: &mut R
) -> Result<(), KyberError>
  where R: CryptoRng + RngCore
{
  let mut buf = [0u8; 2*KYBER_SYMBYTES];
  crypto_kem_enc(send, &mut buf, recv, rng, None)?;
  crypto_kem_dec(&mut buf[KYBER_SYMBYTES..], &recv[KYBER_PUBLICKEYBYTES..], skb)?;
  shake256(k, KYBER_SYMBYTES as u64, &buf, 2*KYBER_SYMBYTES as u64);
  Ok(())
}

/// Unilaterally authenticated key exchange computation by Alice
pub fn uake_shared_a(
  k: &mut[u8], 
  recv: &[u8], 
  tk: &[u8], 
  sk: &[u8]
) -> Result<(), KyberError> 
{
  let mut buf = [0u8; 2*KYBER_SYMBYTES];
  crypto_kem_dec(&mut buf, recv, sk)?;
  buf[KYBER_SYMBYTES..].copy_from_slice(&tk[..]);
  shake256(k, KYBER_SYMBYTES as u64, &buf, 2*KYBER_SYMBYTES as u64);
  Ok(())
}

/// Authenticated key exchange initiation by Alice
pub fn ake_init_a<R>(
  send: &mut[u8], 
  tk: &mut[u8], 
  sk: &mut[u8], 
  pkb: &[u8],
  rng: &mut R
) -> Result<(), KyberError>
  where R: CryptoRng + RngCore
{
  crypto_kem_keypair(send, sk, rng, None)?;
  crypto_kem_enc(&mut send[KYBER_PUBLICKEYBYTES..], tk, pkb, rng, None)?;
  Ok(())
}

/// Mutually authenticated key exchange computation by Bob
pub fn ake_shared_b<R>(
  send: &mut[u8], 
  k: &mut[u8], 
  recv: &[u8], 
  skb: &[u8], 
  pka: &[u8],
  rng: &mut R
) -> Result<(), KyberError> 
  where R: CryptoRng + RngCore
{
  let mut buf = [0u8; 3*KYBER_SYMBYTES];
  crypto_kem_enc(send, &mut buf, recv, rng, None)?;
  crypto_kem_enc(&mut send[KYBER_CIPHERTEXTBYTES..], &mut buf[KYBER_SYMBYTES..], pka, rng, None)?;
  crypto_kem_dec(&mut buf[2*KYBER_SYMBYTES..], &recv[KYBER_PUBLICKEYBYTES..], skb)?;
  shake256(k, KYBER_SYMBYTES as u64, &buf, 3*KYBER_SYMBYTES as u64);
  Ok(())
}

/// Mutually authenticated key exchange computation by Alice
pub fn ake_shared_a(
  k: &mut[u8], 
  recv: &[u8], 
  tk: &[u8], 
  sk: &[u8], 
  ska: &[u8]
) -> Result<(), KyberError> 
{
  let mut buf = [0u8; 3*KYBER_SYMBYTES];
  crypto_kem_dec(&mut buf, recv, sk)?;
  crypto_kem_dec(&mut buf[KYBER_SYMBYTES..], &recv[KYBER_CIPHERTEXTBYTES..], ska)?;
  buf[2*KYBER_SYMBYTES..].copy_from_slice(&tk[..]);
  shake256(k, KYBER_SYMBYTES as u64, &buf, 3*KYBER_SYMBYTES as u64);
  Ok(())
}