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
//! // Initializes the rng and public/private keypair 
//! let mut alice = Kyber::initialize(&mut rng)?;
//! let mut bob = Kyber::initialize(&mut rng)?;
//! 
//! // Public keys
//! let alice_public_key = alice.keys.public;
//! let bob_public_key = bob.keys.public;
//! 
//! // Alice initiates key exchange
//! let client_init = alice.ake_client_init(bob_public_key, &mut rng)?;
//! 
//! // Bob authenticates and responds
//! let server_send = bob.ake_server_receive(client_init, alice_public_key, &mut rng)?;
//! 
//! // Alice authenticates the response and decapsulates the shared secret
//! alice.ake_client_confirm(server_send)?;
//! 
//! // Both Kyber structs now have the shared secret
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

// #![no_std]
#![allow(clippy::many_single_char_names)]
#[cfg(all(feature = "kyber1024", feature = "kyber512"))]
compile_error!("Only one security level can be specified");

#[cfg(feature = "90s")] 
mod aes256;

#[cfg(all(target_arch = "x86_64", not(feature = "reference")))] 
mod avx2;
#[cfg(all(target_arch = "x86_64", not(feature = "reference")))] 
use avx2::*;
#[cfg(any(not(target_arch = "x86_64"), feature = "reference"))] 
mod reference;
#[cfg(any(not(target_arch = "x86_64"), feature = "reference"))] 
use reference::*;

mod api;
mod error;
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
pub use api::*;

/// Result of encapsulating a public key which includes the ciphertext and shared secret
pub type Encapsulated =  Result<([u8; KYBER_CIPHERTEXTBYTES], [u8; KYBER_SSBYTES]), KyberError>;
/// The result of  decapsulating a ciphertext which produces a shared secret when confirmed
pub type Decapsulated = Result<[u8; KYBER_SSBYTES], KyberError>;
/// Kyber public key
pub type PublicKey = [u8; KYBER_PUBLICKEYBYTES];
/// Kyber secret key
pub type SecretKey = [u8; KYBER_SECRETKEYBYTES];
/// Bytes to send when initiating a unilateral key exchange
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Kyber {
  /// A public/private keypair for key exchanges
  /// Kyber is designed to be safe against key re-use
  pub keys: Keypair,
  /// The resulting symmetrical shared secret from a key exchange
  pub shared_secret: [u8; KYBER_SSBYTES],
  /// Sent when initiating a key exchange
  pub uake_send_a: UakeSendA,
  /// Sent back responding to a key exchange initiation
  pub uake_send_b: UakeSendB,
  /// Sent when initiating a key exchange
  pub ake_send_a: AkeSendA,
  /// Sent bak when responding to a key exchange initiation
  pub ake_send_b: AkeSendB,
  /// Flag to check random keypair has been generated
  pub initialized: bool,

  // Ephermal keys
  temp_key: TempKey,
  eska: Eska
}

impl Default for Kyber {
  fn default() -> Self {
    Kyber {
      keys: Keypair::default(),
      shared_secret: [0u8; KYBER_SSBYTES],
      uake_send_a: [0u8; KEX_UAKE_SENDABYTES],
      uake_send_b: [0u8; KEX_UAKE_SENDBBYTES],
      ake_send_a: [0u8; KEX_AKE_SENDABYTES],
      ake_send_b: [0u8; KEX_AKE_SENDBBYTES],
      temp_key: [0u8; KEX_SSBYTES],
      eska: [0u8; KYBER_SECRETKEYBYTES],
      initialized: false
    }
  }
}

impl Kyber {
  /// Builds a Kyber struct with a new generated keypair. 
  /// 
  /// The only difference between this function and `Kyber::default()` 
  /// is key generation and setting the initialized flag.
  /// ```
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// # let mut rng = rand::thread_rng();
  /// let mut alice = Kyber::initialize(&mut rng)?;
  /// assert!(alice.initialized);
  /// assert!(alice.keys != Keypair::default());
  /// # Ok(()) }
  /// ```
  pub fn initialize<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Kyber, KyberError> 
  {
    let keys = keypair(rng)?;
    Ok(Kyber{ keys, initialized: true, ..Default::default() })
  }

  /// Replaces the current keypair with a provided Keypair struct  
  /// and sets the initialization flag true.
  /// ```
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// let mut alice = Kyber::default();
  /// // Key exchange functions will fail if random keypair not generated
  /// assert!(alice.initialized == false);
  /// // Generate a new keypair
  /// let mut rng = rand::thread_rng();
  /// let keypair = Keypair::generate(&mut rng)?;
  /// alice.set_keys(keypair);
  /// assert!(alice.initialized);
  /// assert_eq!(alice.keys, keypair);
  /// # Ok(()) }
  /// ```
  pub fn set_keys(&mut self, keys: Keypair) 
  {
    self.keys = keys;
    self.initialized = true;
  }

  /// Generates a new keypair
  /// ```
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// # let mut rng = rand::thread_rng();
  /// let mut alice = Kyber::initialize(&mut rng)?;
  /// let old_pubkey = alice.keys.public;
  /// alice.new_keys(&mut rng)?;
  /// assert!( old_pubkey != alice.keys.public); 
  /// # Ok(()) }
  /// ```
  pub fn new_keys<R>(&mut self, rng: &mut R) -> Result<(), KyberError> 
    where R: CryptoRng + RngCore
  {
    self.keys = Keypair::generate(rng)?;
    self.initialized = true;
    Ok(())
  }

  /// Initiates a Unilateral Authenticated Key Exchange.
  /// ``` 
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// # let mut rng = rand::thread_rng();
  /// let mut alice = Kyber::initialize(&mut rng)?;
  /// let mut bob = Kyber::initialize(&mut rng)?;
  /// 
  /// let pubkey_bob = bob.keys.public;
  /// let client_init = alice.uake_client_init(pubkey_bob, &mut rng)?;
  /// # Ok(()) }
  /// ```
  pub fn uake_client_init<R>(&mut self, pubkey: PublicKey, rng: &mut R) -> Result<UakeSendA, KyberError> 
    where R: CryptoRng + RngCore
  {
    uake_init_a(
      &mut self.uake_send_a, 
      &mut self.temp_key, 
      &mut self.eska, 
      &pubkey, 
      rng
    )?;
    Ok(self.uake_send_a)
  }

  /// Handles the output of a `uake_client_init()` request
  /// ```
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// # let mut rng = rand::thread_rng();
  /// # let mut alice = Kyber::initialize(&mut rng)?;
  /// # let mut bob = Kyber::initialize(&mut rng)?;
  /// # let pubkey_bob = bob.keys.public;
  /// let client_init = alice.uake_client_init(pubkey_bob, &mut rng)?;
  /// let server_send = bob.uake_server_receive(client_init, &mut rng)?;
  /// # Ok(()) }
  pub fn uake_server_receive<R>(
    &mut self, uake_send_a: UakeSendA, 
    rng: &mut R
  ) -> Result<UakeSendB, KyberError> 
    where R: CryptoRng + RngCore
  {
    uake_shared_b(
      &mut self.uake_send_b, 
      &mut self.shared_secret,
      &uake_send_a, 
      &self.keys.secret,
      rng
    )?;
    Ok(self.uake_send_b)
  }

  /// Decapsulates and authenticates the shared secret from the output of `uake_server_receive()`
  /// ```
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// # let mut rng = rand::thread_rng();
  /// # let mut alice = Kyber::initialize(&mut rng)?;
  /// # let mut bob = Kyber::initialize(&mut rng)?;
  /// # let pubkey_bob = bob.keys.public;
  /// # let client_init = alice.uake_client_init(pubkey_bob, &mut rng)?;
  /// let server_send = bob.uake_server_receive(client_init, &mut rng)?;
  /// let client_confirm = alice.uake_client_confirm(server_send);
  /// assert!(client_confirm.is_ok());
  /// assert_eq!(alice.shared_secret, bob.shared_secret);
  /// # Ok(()) }
  pub fn uake_client_confirm(&mut self, uake_send_b: UakeSendB) -> Result<(), KyberError> 
  {
    uake_shared_a(
      &mut self.shared_secret, 
      &uake_send_b, 
      &self.temp_key, 
      &self.eska
    )?;
    Ok(())
  }

  pub fn ake_client_init<R>(
    &mut self, 
    pubkey: PublicKey,
    rng: &mut R
  ) -> Result<AkeSendA, KyberError>
    where R: CryptoRng + RngCore
  {
    ake_init_a(
      &mut self.ake_send_a, 
      &mut self.temp_key, 
      &mut self.eska, 
      &pubkey, 
      rng
    )?;
    Ok(self.ake_send_a)
  }

  pub fn ake_server_receive<R>(
    &mut self, 
    ake_send_a: AkeSendA, 
    pubkey: PublicKey,
    rng: &mut R
  ) 
  -> Result<AkeSendB, KyberError>
    where R: CryptoRng + RngCore 
  {
    ake_shared_b(
      &mut self.ake_send_b, 
      &mut self.shared_secret, 
      &ake_send_a, 
      &self.keys.secret, 
      &pubkey, 
      rng
    )?;
    Ok(self.ake_send_b)
  }

  pub fn ake_client_confirm(
    &mut self, 
    ake_send_b: AkeSendB
  ) -> Result<(), KyberError> 
  {
    ake_shared_a(
      &mut self.shared_secret, 
      &ake_send_b, 
      &self.temp_key, 
      &self.eska, 
      &self.keys.secret)?;
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
/// let publickey = keys.public;
/// let secretkey = keys.secret;
/// assert_eq!(publickey.len(), KYBER_PUBLICKEYBYTES);
/// assert_eq!(secretkey.len(), KYBER_SECRETKEYBYTES);
/// # Ok(())}
/// ```
pub fn keypair<R>(rng: &mut R) -> Result<Keypair, KyberError> 
  where R: RngCore + CryptoRng
{
  let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
  let mut sk = [0u8; KYBER_SECRETKEYBYTES];
  api::crypto_kem_keypair(&mut pk, &mut sk, rng, None)?;
  Ok( Keypair { public: pk, secret: sk })
}

/// Encapsulates a public key
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
    return Err(KyberError::Encapsulation)
  }
  let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
  let mut ss = [0u8; KYBER_SSBYTES];
  api::crypto_kem_enc(&mut ct, &mut ss, pk, rng, None)?;
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
    return Err(KyberError::Decapsulation)
  }
  let mut ss = [0u8; KYBER_SSBYTES];
  match api::crypto_kem_dec(&mut ss, ct, sk) {
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

