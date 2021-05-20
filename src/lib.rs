//! # Kyber
//! 
//! A Rust implementation of the Kyber algorithm
//! 
//! ## Usage 
//! The Kyber struct is a higher-level construction for unilateral and mutual key exchange. 
//! 
//!
//! #### Mutually Authenticated Key Exchange
//! 
//! ```
//! use pqc_kyber::*;
//! 
//! # fn main() -> Result<(),KyberError> {
//! let mut rng = rand::thread_rng();
//! 
//! // Initialize the key exchange structs
//! let mut alice = Ake::new();
//! let mut bob = Ake::new();
//! 
//! // Generate Keypairs
//! let alice_keys = Keypair::generate(&mut rng)?;
//! let bob_keys = Keypair::generate(&mut rng)?;
//! 
//! // Alice initiates key exchange
//! let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
//! 
//! // Bob authenticates and responds
//! let server_send = bob.server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)?;
//! 
//! // Alice authenticates the response and decapsulates the shared secret
//! alice.client_confirm(server_send, &alice_keys.secret)?;
//! 
//! // Both key exchange structs now have the shared secret
//! assert_eq!(alice.shared_secret, bob.shared_secret);
//! # Ok(()) }
//! ```
//! ##### Key Encapsulation
//! Lower level functions using the Kyber algorithm directly.
//! ```
//! # use pqc_kyber::*;
//! # fn main() -> Result<(),KyberError> {
//! # let mut rng = rand::thread_rng();
//! // Generate Keypair
//! let keys_bob = keypair(&mut rng);
//! 
//! // Alice encapsulates a shared secret using Bob's public key
//! let (ciphertext, shared_secret_alice) = encapsulate(&keys_bob.public, &mut rng)?;
//! 
//! // Bob decapsulates a shared secret using the ciphertext sent by Alice 
//! let shared_secret_bob = decapsulate(&ciphertext, &keys_bob.secret)?;
//! 
//! assert_eq!(shared_secret_alice, shared_secret_bob);
//! # Ok(()) }
//! ```

#![no_std]
#![allow(clippy::many_single_char_names)]

// Prevent usage of mutually exclusive features
#[cfg(all(feature = "kyber1024", feature = "kyber512"))]
compile_error!("Only one security level can be specified");

#[cfg(all(target_arch = "x86_64", not(feature = "reference")))] 
mod avx2;
#[cfg(all(target_arch = "x86_64", not(feature = "reference")))] 
use avx2::*;
#[cfg(any(not(target_arch = "x86_64"), feature = "reference"))] 
mod reference;
#[cfg(any(not(target_arch = "x86_64"), feature = "reference"))] 
use reference::*;

mod error;
mod kem;
mod kex;
mod params;
mod rng;
mod symmetric;

pub use rand_core::{RngCore, CryptoRng};
pub use kex::*;
pub use error::KyberError;
pub use params::*;

// Feature workaround to expose private functions for Known Answer Tests
#[cfg(feature="KATs")]
pub use kem::*;

/// Keypair generation with a provided RNG.
/// 
/// ### Example
/// ```
/// # use pqc_kyber::*;
/// # fn main() -> Result<(), KyberError> {
/// let mut rng = rand::thread_rng();
/// let keys = pqc_kyber::keypair(&mut rng)?;
/// # Ok(())}
/// ```
pub fn keypair<R>(rng: &mut R) -> Keypair 
  where R: RngCore + CryptoRng
{
  let mut public = [0u8; KYBER_PUBLICKEYBYTES];
  let mut secret = [0u8; KYBER_SECRETKEYBYTES];
  kem::crypto_kem_keypair(&mut public, &mut secret, rng, None);
  Keypair { public, secret }
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
/// let (ct, ss) = encapsulate(&keys.public, &mut rng)?;
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
  kem::crypto_kem_enc(&mut ct, &mut ss, pk, rng, None)?;
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
  match kem::crypto_kem_dec(&mut ss, ct, sk) {
    Ok(_) => Ok(ss),
    Err(e) => Err(e)
  }
}

/// Contains a public/private keypair
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Keypair {
    pub public: PublicKey,
    pub secret: SecretKey
}

impl Default for Keypair {
  fn default() -> Self {
    Keypair {
      public: [0u8; KYBER_PUBLICKEYBYTES],
      secret: [0u8; KYBER_SECRETKEYBYTES]
    }
  }
}

impl Keypair {
  /// Securely generates a new keypair`
  /// ```
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(), KyberError> {
  /// let mut rng = rand::thread_rng();
  /// let keys = Keypair::generate(&mut rng);
  /// # let empty_keys = Keypair::default();
  /// # assert!(empty_keys != keys); 
  /// # Ok(()) }
  /// ```
  pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Keypair {
    keypair(rng)
  }
}

