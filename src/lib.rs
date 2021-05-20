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
//! let keys_bob = keypair(&mut rng)?;
//! 
//! // Encapsulate
//! let (ciphertext, shared_secret_alice) = encapsulate(&keys_bob.public, &mut rng)?;
//! 
//! // Decapsulate
//! let shared_secret_bob = decapsulate(&ciphertext, &keys_bob.secret)?;
//! 
//! assert_eq!(shared_secret_alice, shared_secret_bob);
//! # Ok(()) }
//! ```

#![no_std]
#![allow(clippy::many_single_char_names)]
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

/// Result of encapsulating a public key which includes the ciphertext and shared secret
pub type Encapsulated =  Result<([u8; KYBER_CIPHERTEXTBYTES], [u8; KYBER_SSBYTES]), KyberError>;
/// The result of  decapsulating a ciphertext which produces a shared secret when confirmed
pub type Decapsulated = Result<[u8; KYBER_SSBYTES], KyberError>;
/// Kyber public key
pub type PublicKey = [u8; KYBER_PUBLICKEYBYTES];
/// Kyber secret key
pub type SecretKey = [u8; KYBER_SECRETKEYBYTES];
/// Bytes to send when initiating a unilateral key exchange

/// Kyber Shared Secret
pub type SharedSecret = [u8; KYBER_SSBYTES]; 

pub type UakeSendA = [u8; KEX_UAKE_SENDABYTES]; 
/// Bytes to send when responding to a unilateral key exchange
pub type UakeSendB = [u8; KEX_UAKE_SENDBBYTES]; 
/// Bytes to send when initiating a mutual key exchange
pub type AkeSendA = [u8; KEX_AKE_SENDABYTES]; 
/// Bytes to send when responding to a mutual key exchange
pub type AkeSendB = [u8; KEX_AKE_SENDBBYTES]; 

// Ephemeral keys
type TempKey = [u8; KEX_SSBYTES];
type Eska = [u8; KYBER_SECRETKEYBYTES];

// TODO: implement zeroise feature
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Uake {
  /// The resulting shared secret from a key exchange
  pub shared_secret: SharedSecret,
  /// Sent when initiating a key exchange
  pub send_a: UakeSendA,
  /// Response to a key exchange initiation
  pub send_b: UakeSendB,

  // Epheremal keys
  temp_key: TempKey,
  eska: Eska
}

impl Default for Uake {
  fn default() -> Self {
    Uake {
      shared_secret: [0u8; KYBER_SSBYTES],
      send_a: [0u8; KEX_UAKE_SENDABYTES],
      send_b: [0u8; KEX_UAKE_SENDBBYTES],
      temp_key: [0u8; KEX_SSBYTES],
      eska: [0u8; KYBER_SECRETKEYBYTES],
    }
  }
}

impl Uake {
  /// A new unilaterally authenticated key exchange
  /// ```
  /// let kex = Uake::new();
  /// ```
  pub fn new() -> Self {
    Self::default()
  }

  /// Initiates a Unilateral Authenticated Key Exchange.
  /// ``` 
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// let mut rng = rand::thread_rng();
  /// let alice = Uake::new();
  /// let bob_keys = Keypair::generate(&mut rng)?;
  /// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
  /// # Ok(()) }
  /// ```
  pub fn client_init<R>(&mut self, pubkey: &PublicKey, rng: &mut R) 
  -> Result<UakeSendA, KyberError> 
    where R: CryptoRng + RngCore
  {
    uake_init_a(
      &mut self.send_a, &mut self.temp_key, 
      &mut self.eska, pubkey, rng
    )?;
    Ok(self.send_a)
  }

  /// Handles the output of a `client_init()` request
  /// ```
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// # let mut rng = rand::thread_rng();
  /// let mut alice = Uake::new();
  /// let mut bob = Uake::new();
  /// let mut bob_keys = Keypair::generate(&mut rng)?;
  /// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
  /// let server_send = bob.server_receive(client_init, &mut rng)?;
  /// # Ok(()) }
  pub fn server_receive<R>(
    &mut self, send_a: UakeSendA, secretkey: &SecretKey, rng: &mut R
  ) 
  -> Result<UakeSendB, KyberError> 
    where R: CryptoRng + RngCore
  {
    uake_shared_b(
      &mut self.send_b, &mut self.shared_secret,
      &send_a, secretkey, rng
    )?;
    Ok(self.send_b)
  }

  /// Decapsulates and authenticates the shared secret from the output of 
  /// `server_receive()`
  /// ```
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// # let mut rng = rand::thread_rng();
  /// # let mut alice = Uake::new();
  /// # let mut bob = Uake::new();
  /// # let mut bob_keys = Keypair::generate(&mut rng)?;
  /// let client_init = alice.client_init(bob_keys.public, &mut rng)?;
  /// let server_send = bob.server_receive(client_init, &mut rng)?;
  /// let client_confirm = alice.client_confirm(server_send);
  /// assert_eq!(alice.shared_secret, bob.shared_secret);
  /// # Ok(()) }
  pub fn client_confirm(&mut self, send_b: UakeSendB) 
  -> Result<(), KyberError> 
  {
    uake_shared_a(
      &mut self.shared_secret, &send_b, 
      &self.temp_key, &self.eska
    )?;
    Ok(())
  }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Ake {
  /// The resulting symmetrical shared secret from a key exchange
  pub shared_secret: SharedSecret,
  /// Sent when initiating a key exchange
  pub send_a: AkeSendA,
  /// Sent back responding to a key exchange initiation
  pub send_b: AkeSendB,

  // Epheremal keys
  temp_key: TempKey,
  eska: Eska
}

impl Default for Ake {
  fn default() -> Self {
    Ake {
      shared_secret: [0u8; KYBER_SSBYTES],
      send_a: [0u8; KEX_AKE_SENDABYTES],
      send_b: [0u8; KEX_AKE_SENDBBYTES],
      temp_key: [0u8; KEX_SSBYTES],
      eska: [0u8; KYBER_SECRETKEYBYTES],
    }
  }
}

impl Ake {
  /// A new mutually authenticated key exchange
  /// ```
  /// let kex = Ake::new();
  /// ```
  pub fn new() -> Self {
    Self::default()
  }

  /// Initiates a Mutually Authenticated Key Exchange.
  /// ``` 
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// let mut rng = rand::thread_rng();
  /// let alice = Ake::new();
  /// let bob_keys = Keypair::generate(&mut rng)?;
  /// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
  /// # Ok(()) }
  /// ```
  pub fn client_init<R>(&mut self, pubkey: PublicKey, rng: &mut R) 
  -> Result<AkeSendA, KyberError>
    where R: CryptoRng + RngCore
  {
    ake_init_a(
      &mut self.send_a, &mut self.temp_key, 
      &mut self.eska, &pubkey, rng
    )?;
    Ok(self.send_a)
  }

  /// Handles and authenticates the output of a `client_init()` request
  /// ```
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// # let mut rng = rand::thread_rng();
  /// let mut alice = Ake::new();
  /// let mut bob = Ake::new();
  /// let mut alice_keys = Keypair::generate(&mut rng)?;
  /// let mut bob_keys = Keypair::generate(&mut rng)?;
  /// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
  /// let server_send = bob.server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)?;
  /// # Ok(()) }
  pub fn server_receive<R>(
    &mut self, ake_send_a: AkeSendA, pubkey: &PublicKey, 
    secretkey: &SecretKey, rng: &mut R
  ) 
  -> Result<AkeSendB, KyberError>
    where R: CryptoRng + RngCore 
  {
    ake_shared_b(
      &mut self.send_b, &mut self.shared_secret, 
      &ake_send_a, secretkey, pubkey, rng
    )?;
    Ok(self.send_b)
  }

  /// Decapsulates and authenticates the shared secret from the output of 
  /// `server_receive()`
  /// ```
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// # let mut rng = rand::thread_rng();
  /// let mut alice = Ake::new();
  /// let mut bob = Ake::new();
  /// let mut alice_keys = Keypair::generate(&mut rng)?;
  /// let mut bob_keys = Keypair::generate(&mut rng)?;
  /// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
  /// let server_send = bob.server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)?;
  /// let client_confirm = alice.client_confirm(server_send, &alice_keys.secret);
  /// assert_eq!(alice.shared_secret, bob.shared_secret);
  /// # Ok(()) }
  pub fn client_confirm(&mut self, send_b: AkeSendB, secretkey: &SecretKey) 
  -> Result<(), KyberError> 
  {
    ake_shared_a(
      &mut self.shared_secret, &send_b, 
      &self.temp_key, &self.eska, secretkey
    )?;
    Ok(())
  }
}

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
pub fn keypair<R>(rng: &mut R) -> Result<Keypair, KyberError> 
  where R: RngCore + CryptoRng
{
  let mut public = [0u8; KYBER_PUBLICKEYBYTES];
  let mut secret = [0u8; KYBER_SECRETKEYBYTES];
  kem::crypto_kem_keypair(&mut public, &mut secret, rng, None)?;
  Ok( Keypair { public, secret })
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
  match kem::crypto_kem_dec(&mut ss, ct, sk) {
    Ok(_) => Ok(ss),
    Err(e) => Err(e)
  }
}

/// Contains a public/private keypair
#[derive(Copy, Clone, Debug, PartialEq)]
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
  /// let keys = Keypair::generate(&mut rng)?;
  /// # let empty_keys = Keypair::default();
  /// # assert!(empty_keys != keys); 
  /// # Ok(()) }
  /// ```
  pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Keypair, KyberError> {
    keypair(rng)
  }
}

