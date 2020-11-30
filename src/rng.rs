use rand_core::*;
use crate::error::KyberError;

pub fn randombytes<R>(x: &mut [u8], len: usize, rng: &mut R) -> Result<(), KyberError>
  where R: RngCore + CryptoRng,
{
  match rng.try_fill_bytes(&mut x[..len]) {
    Ok(_) => Ok(()),
    Err(e) => Err(KyberError::KeyPair(e))
  }
}
