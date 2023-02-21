#[cfg(feature = "zeroize")]
use zeroize::Zeroize;
use crate::{
  params::*, 
  error::KyberError,
  RngCore, CryptoRng,
  kem::*,
  kex::{PublicKey, SecretKey, Encapsulated, Decapsulated}
};

/// Keypair generation with a provided RNG.
/// 
/// ### Example
/// ```
/// # use pqc_kyber::*;
/// let mut rng = rand::thread_rng();
/// let keys = keypair(&mut rng);
/// ```
pub fn keypair<R>(rng: &mut R) -> Keypair 
  where R: RngCore + CryptoRng
{
  let mut public = [0u8; KYBER_PUBLICKEYBYTES];
  let mut secret = [0u8; KYBER_SECRETKEYBYTES];
  crypto_kem_keypair(&mut public, &mut secret, rng, None);
  let keys  = Keypair { public, secret };
  zeroize!(secret);
  keys
}

/// Encapsulates a public key returning the ciphertext to send
/// and the shared secret
///
/// ### Example
/// ```
/// # use pqc_kyber::*; 
/// # fn main() -> Result<(), KyberError> {
/// let mut rng = rand::thread_rng();
/// let keys = keypair(&mut rng);
/// let (ciphertext, shared_secret) = encapsulate(&keys.public, &mut rng)?;
/// # Ok(())}
/// ```
pub fn encapsulate<R>(pk: &[u8], rng: &mut R) -> Encapsulated
  where R: CryptoRng + RngCore
{
  if pk.len() != KYBER_PUBLICKEYBYTES {
    return Err(KyberError::InvalidInput)
  }
  let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
  let mut ss = [0u8; KYBER_SSBYTES];
  crypto_kem_enc(&mut ct, &mut ss, pk, rng, None);
  Ok((ct, ss))
}

/// Decapsulates ciphertext with a secret key, the result will contain
/// a KyberError if decapsulation fails
///
/// ### Example
/// ```
/// # use pqc_kyber::*;
/// # fn main() -> Result<(), KyberError> {
/// let mut rng = rand::thread_rng();
/// let keys = keypair(&mut rng);
/// let (ct, ss1) = encapsulate(&keys.public, &mut rng)?;
/// let ss2 = decapsulate(&ct, keys.expose_secret())?;
/// assert_eq!(ss1, ss2);
/// #  Ok(())}
/// ```
pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Decapsulated 
{
  if ct.len() != KYBER_CIPHERTEXTBYTES || sk.len() != KYBER_SECRETKEYBYTES {
    return Err(KyberError::InvalidInput)
  }
  let mut ss = [0u8; KYBER_SSBYTES];
  match crypto_kem_dec(&mut ss, ct, sk) {
    Ok(_) => Ok(ss),
    Err(e) => Err(e)
  }
}

/// A public/secret keypair for use with Kyber. 
/// 
/// Byte lengths of the keys are determined by the security level chosen.
#[derive(Clone)]
pub struct Keypair {
    pub public: PublicKey,
    secret: SecretKey,
}

impl Keypair {
  /// Securely generates a new keypair`
  /// ```
  /// # use pqc_kyber::*;
  /// let mut rng = rand::thread_rng();
  /// let keys = Keypair::generate(&mut rng);
  /// ```
  pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Keypair {
    keypair(rng)
  }

  /// Explicitly exposes the secret key
  ///```
  /// # use pqc_kyber::*;
  /// # let mut rng = rand::thread_rng();
  /// let keys = Keypair::generate(&mut rng);
  /// let secret = keys.expose_secret();
  /// # assert!(secret.len() == KYBER_SECRETKEYBYTES); 
  /// ```
  pub fn expose_secret(&self) -> &SecretKey {
    &self.secret
  }
}

#[cfg(feature = "zeroize")]
impl Drop for Keypair {
  fn drop(&mut self) {
    self.secret.zeroize()
  }
}

/// Elides the secret key, to debug it use [`Keypair::expose_secret()`]
impl core::fmt::Debug for Keypair {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
      write!(f, "{{ public: '{:x?}',\n secret: 'ELIDED'}}", self.public)
  }
}

/// Ignores secret key to avoid leakage from of a non-cryptographic hasher
impl core::hash::Hash for Keypair {
  fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
    self.public.hash(state);
  }
}

/// Non-constant time equality comparison, only checks public keys
impl PartialEq for Keypair {
  fn eq(&self, other: &Keypair) -> bool {
    self.public == other.public
  }
}

impl Eq for Keypair {}

/// Helper function for zeroing the target if the `zeroize` feature is enabled. 
/// 
/// Used for code brevity.
///  
/// Replaces:
/// 
/// ```ignore
/// #[cfg(feature = "zeroize")]
/// target.zeroize();
/// ``` 
/// 
/// ### Arguments:
/// 
/// * target, which implements Zeroize
/// 
/// ### Usage:
/// ```ignore
/// zeroize!(target);
/// ```
macro_rules! zeroize {
  ($target: ident) => {
    #[cfg(feature = "zeroize")]
    $target.zeroize(); 
  };
}

pub use zeroize;
