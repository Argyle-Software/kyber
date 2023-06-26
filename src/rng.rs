use rand_core::*;
use crate::KyberError;

// Fills buffer x with len bytes, RNG must satisfy the 
// RngCore trait and CryptoRng marker trait requirements
pub fn randombytes<R>(x: &mut [u8], len: usize, rng: &mut R) -> Result<(), KyberError>
  where R: RngCore + CryptoRng,
{
  match rng.try_fill_bytes(&mut x[..len]) {
    Ok(_) => Ok(()),
    Err(_) => Err(KyberError::RandomBytesGeneration)
  }
}
