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
/// # fn main() -> Result<(), KyberError> {
/// let mut rng = rand::thread_rng();
/// let keys = keypair(&mut rng)?;
/// # Ok(())}
/// ```
pub fn keypair<R>(rng: &mut R) -> Result<Keypair, KyberError>
  where R: RngCore + CryptoRng
{
  let mut public = [0u8; KYBER_PUBLICKEYBYTES];
  let mut secret = [0u8; KYBER_SECRETKEYBYTES];
  crypto_kem_keypair(&mut public, &mut secret, rng, None)?;
  Ok(Keypair { public, secret })
}

/// Encapsulates a public key returning the ciphertext to send
/// and the shared secret
///
/// ### Example
/// ```
/// # use pqc_kyber::*; 
/// # fn main() -> Result<(), KyberError> {
/// let mut rng = rand::thread_rng();
/// let keys = keypair(&mut rng)?;
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
  crypto_kem_enc(&mut ct, &mut ss, pk, rng, None)?;
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
/// let keys = keypair(&mut rng)?;
/// let (ct, ss1) = encapsulate(&keys.public, &mut rng)?;
/// let ss2 = decapsulate(&ct, &keys.secret)?;
/// assert_eq!(ss1, ss2);
/// #  Ok(())}
/// ```
pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Decapsulated 
{
  if ct.len() != KYBER_CIPHERTEXTBYTES || sk.len() != KYBER_SECRETKEYBYTES {
    return Err(KyberError::InvalidInput)
  }
  let mut ss = [0u8; KYBER_SSBYTES];
  crypto_kem_dec(&mut ss, ct, sk);
  Ok(ss)
}

/// A public/secret keypair for use with Kyber. 
/// 
/// Byte lengths of the keys are determined by the security level chosen.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Keypair {
    pub public: PublicKey,
    pub secret: SecretKey
}

impl Keypair {
  /// Securely generates a new keypair`
  /// ```
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(), KyberError> {
  /// let mut rng = rand::thread_rng();
  /// let keys = Keypair::generate(&mut rng)?;
  /// # let empty_keys = Keypair{
  ///   public: [0u8; KYBER_PUBLICKEYBYTES], secret: [0u8; KYBER_SECRETKEYBYTES]
  /// };
  /// # assert!(empty_keys != keys); 
  /// # Ok(()) }
  /// ```
  pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Keypair, KyberError> {
    keypair(rng)
  }
}

struct DummyRng{}
impl CryptoRng for DummyRng{}
impl RngCore for DummyRng{
    fn next_u32(&mut self) -> u32 { panic!() }
    fn next_u64(&mut self) -> u64 { panic!() }
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> { panic!() }
    fn fill_bytes(&mut self, _dest: &mut [u8]) { panic!() }
}

/// Deterministically derive a keypair from a seed as specified
/// in draft-schwabe-cfrg-kyber.
pub fn derive(seed: &[u8]) -> Result<Keypair, KyberError>
{
  let mut public = [0u8; KYBER_PUBLICKEYBYTES];
  let mut secret = [0u8; KYBER_SECRETKEYBYTES];
  let mut _rng = DummyRng{};
  if seed.len() != 64 {
    return Err(KyberError::InvalidInput)
  }
  crypto_kem_keypair(&mut public, &mut secret, &mut _rng, Some((&seed[..32], &seed[32..])))?;
  Ok(Keypair { public, secret })
}

/// Extracts public key from private key.
pub fn public(sk: &[u8]) -> PublicKey
{
  let mut pk = [0u8; KYBER_INDCPA_PUBLICKEYBYTES];
  pk.copy_from_slice(
    &sk[KYBER_INDCPA_SECRETKEYBYTES
               ..KYBER_INDCPA_SECRETKEYBYTES+KYBER_INDCPA_PUBLICKEYBYTES]
  );
  pk
}
