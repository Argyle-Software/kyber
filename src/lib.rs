#![allow(clippy::many_single_char_names)]
//! # Kyber
//! 
//! A pure rust implementation of the Kyber algorithm.
//! 
//! 
//! To select different security strengths from the default enable 
//! in your `cargo.toml` the feature of `kyber512` or `kyber1024` 
//! 
//! ## Usage 
//!
//! It is recommended to use the Kyber struct and its in-built methods 
//! for key exchange.
//! ```
//! use pqc_kyber::*;
//! 
//! // Initializes the rng and public/private keypair 
//! let mut alice = Kyber::initialize().unwrap();
//! let mut bob = Kyber::initialize().unwrap();
//! 
//! // Public keys
//! let alice_public_key = alice.keys.public;
//! let bob_public_key = bob.keys.public;
//! 
//! // Alice initiates key exchange
//! let uake_send_a = alice.uake_initiate(bob_public_key).unwrap();
//! 
//! // Bob receives the initiation request
//! let uake_send_b = bob.uake_receive(uake_send_a).unwrap();
//! 
//! // Alice gets a response
//! alice.uake_confirm(uake_send_b).unwrap();
//! 
//! // Both Kyber structs now have the shared secret
//! assert_eq!(alice.shared_secret, bob.shared_secret);
//! 
//! ```
//! ##### Key Encapsulation
//! Lower level functions using the Kyber algortihm directly.
//! ```
//! # use pqc_kyber::*;
//! // Generate Keypair
//! let mut rng = rand::thread_rng();
//! let keys = keypair(&mut rng).unwrap();
//! 
//! // Encapsulate
//! let (ct, shared_secret_alice) = encapsulate(&keys.public, &mut rng).unwrap();
//! 
//! // Decapsulate
//! let shared_secret_bob = decapsulate(&ct, &keys.secret).unwrap();
//! 
//! assert_eq!(shared_secret_alice, shared_secret_bob);
//! ```


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
use rand::prelude::*;
pub use rand_core::{RngCore, CryptoRng};
pub use kex::*;
pub use error::KyberError;
pub use params::{
  KYBER_PUBLICKEYBYTES, 
  KYBER_SECRETKEYBYTES, 
  KYBER_CIPHERTEXTBYTES, 
  KYBER_SSBYTES, 
  KYBER_K, 
  KYBER_90S
};

/// The result of encapsulating a public key which incleudes Ciphertext and a temporary key 
pub type Encapsulated =  Result<([u8; KYBER_CIPHERTEXTBYTES], [u8; KYBER_SSBYTES]), KyberError>;
/// The result of  decapsulating a ciphertext which produces a shared secret when confirmed
pub type Decapsulated = Result<[u8; KYBER_SSBYTES], KyberError>;
/// A Kyber public key
pub type PublicKey = [u8; KYBER_PUBLICKEYBYTES];
/// A Kyber secret key
pub type SecretKey = [u8; KYBER_SECRETKEYBYTES];
/// The bytes to send when initiating a uilateral key exchange
pub type UakeSendA = [u8; KEX_UAKE_SENDABYTES]; 
/// The bytes to send when responding to a unilateral key exchange
pub type UakeSendB = [u8; KEX_UAKE_SENDBBYTES]; 
/// The bytes to send when initiating a mutual key exchange
pub type AkeSendA = [u8; KEX_AKE_SENDABYTES]; 
/// The bytes to send when responding to a mutual key exchange
pub type AkeSendB = [u8; KEX_AKE_SENDBBYTES]; 

// Ephermeral internal keys
type TempKey = [u8; KEX_SSBYTES];
type Eska = [u8; KYBER_SECRETKEYBYTES];

#[derive(Copy, Clone, Debug)]
pub struct Kyber {
  /// A public/private keypair for key exchanges
  /// Kyber is designed to be safe for key re-use and this value can
  /// remain static if needed
  pub keys: Keys,
  /// The resulting symeticrical shared secret from a key exchange
  pub shared_secret: [u8; KYBER_SSBYTES],
  /// Sent when initiating a key exchange
  pub uake_send_a: UakeSendA,
  /// Sent back responding to a key exchange initiation
  pub uake_send_b: UakeSendB,
  /// Sent when initiating a key exchange
  pub ake_send_a: AkeSendA,
  /// Sent bak when responding to a key exchange initiation
  pub ake_send_b: AkeSendB,

  // To use other RNG's use lower level contructions 
  rng: ThreadRng,
  // Ephermal key
  temp_key: TempKey,
  // Ephemeral secret key
  eska: Eska,
  /// Flag to note that keypair has been set 
  pub initialized: bool
}

impl Default for Kyber {
  fn default() -> Self {
    Kyber {
      rng: rand::thread_rng(),
      keys: Keys::default(),
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
  /// is the key generation and setting the initialized flag.
  /// 
  /// ```
  /// # use pqc_kyber::*;
  /// let mut alice = Kyber::initialize().unwrap();
  /// assert!(alice.keys != Keys::default());
  /// ```
  pub fn initialize() -> Result<Kyber, KyberError> {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng)?;
    Ok( Kyber {
      rng,
      keys,
      initialized: true,
      ..Default::default()
    })
  }

  /// Replaces the current keypair with a provided Keys struct
  /// ```
  /// # use pqc_kyber::*;
  /// let mut alice = Kyber::default();
  /// // Key exchange functions will fail if struct not initialized
  /// assert!(alice.initialized == false);
  /// // Generate a new keypair
  /// let keypair = Keys::generate().unwrap();
  /// // Set the keys
  /// alice.set_keys(keypair);
  /// # assert_eq!(alice.keys, keypair);
  /// # assert!(alice.initialized);
  /// ```
  pub fn set_keys(&mut self, keys: Keys) {
    self.keys = keys;
    self.initialized = true;
  }

  /// Generates a new keypair
  /// ```
  /// # use pqc_kyber::*;
  /// let mut alice = Kyber::initialize().unwrap();
  /// let old_pubkey = alice.keys.public;
  /// alice.new_keys().unwrap();
  /// assert!( old_pubkey != alice.keys.public); 
  /// ```
  pub fn new_keys(&mut self) -> Result<(), KyberError> {
    self.keys = Keys::generate()?;
    self.initialized = true;
    Ok(())
  }

  /// Initiates a Unilateral Authenticated Key Exchange.
  /// ``` 
  /// # use pqc_kyber::*;
  /// # fn main() -> Result<(),KyberError> {
  /// let mut alice = Kyber::initialize()?;
  /// let mut bob = Kyber::initialize()?;
  /// 
  /// let pubkey_bob = bob.keys.public;
  /// let uake_send_a = alice.uake_initiate(pubkey_bob)?;
  /// # Ok(())
  /// # }
  /// ```
  pub fn uake_initiate(&mut self, pubkey: PublicKey) -> Result<UakeSendA, KyberError> {
    uake_init_a(
      &mut self.uake_send_a, 
      &mut self.temp_key, 
      &mut self.eska, 
      &pubkey, 
      &mut self.rng)?;
    Ok(self.uake_send_a)
  }

  /// Handles the output of a `uake_initiate()` request and provides a response
  /// ```
  /// # use pqc_kyber::*;
  /// # let mut alice = Kyber::initialize().expect("Kyber initialization");
  /// # let mut bob = Kyber::initialize().expect("Kyber initialization");
  /// # let pubkey_bob = bob.keys.public;
  /// # let uake_send_a = alice.uake_initiate(pubkey_bob).expect("KEX initiation");
  /// // `uake_send_a` from the key exchange initiation
  /// let uake_send_b = bob.uake_receive(uake_send_a).unwrap();
  pub fn uake_receive(&mut self, uake_send_a: UakeSendA) -> Result<UakeSendB, KyberError> {
    uake_shared_b(
      &mut self.uake_send_b, 
      &mut self.shared_secret,
      &uake_send_a, 
      &self.keys.secret,
      &mut self.rng)?;
    Ok(self.uake_send_b)
  }

  /// Decasulates the shared secret from the output of `uake_receive()`
  /// ```
  /// # use pqc_kyber::*;
  /// # let mut alice = Kyber::initialize().unwrap();
  /// # let mut bob = Kyber::initialize().unwrap();
  /// # let pubkey_bob = bob.keys.public;
  /// # let uake_send_a = alice.uake_initiate(pubkey_bob).unwrap();
  /// # let uake_send_b = bob.uake_receive(uake_send_a).unwrap();
  /// alice.uake_confirm(uake_send_b).unwrap();
  /// # assert_eq!(alice.shared_secret, bob.shared_secret);
  pub fn uake_confirm(&mut self, uake_send_b: UakeSendB) -> Result<(), KyberError> {
    uake_shared_a(
      &mut self.shared_secret, 
      &uake_send_b, 
      &self.temp_key, 
      &self.eska)?;
    Ok(())
  }

  pub fn ake_initiate(
    &mut self, 
    pubkey: PublicKey
  ) -> Result<AkeSendA, KyberError> 
  {
    ake_init_a(
      &mut self.ake_send_a, 
      &mut self.temp_key, 
      &mut self.eska, 
      &pubkey, 
      &mut self.rng)?;
    Ok(self.ake_send_a)
  }

  pub fn ake_receive(&mut self, ake_send_a: AkeSendA, pubkey: PublicKey)
   -> Result<AkeSendB, KyberError> 
   {
    ake_shared_b(
      &mut self.ake_send_b, 
      &mut self.shared_secret, 
      &ake_send_a, 
      &self.keys.secret, 
      &pubkey, 
      &mut self.rng)?;
    Ok(self.ake_send_b)
  }

  pub fn ake_confirm(
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

/// Lower-level keypair generation with a provided RNG.
/// 
/// ### Example
/// ```
/// # use pqc_kyber::*;
/// let mut rng = rand::thread_rng();
/// let keys = pqc_kyber::keypair(&mut rng).unwrap();
/// let publickey = keys.public;
/// let secretkey = keys.secret;
/// assert_eq!(publickey.len(), KYBER_PUBLICKEYBYTES);
/// assert_eq!(secretkey.len(), KYBER_SECRETKEYBYTES);
/// ```
pub fn keypair<R: RngCore + CryptoRng>(
  rng: &mut R
  ) -> Result<Keys, KyberError> 
  {
  let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
  let mut sk = [0u8; KYBER_SECRETKEYBYTES];
  
  api::crypto_kem_keypair(&mut pk, &mut sk, rng, None)?;
  Ok( Keys {
    public: pk,
    secret: sk
  })
}

/// Encapsulates a public key
///
/// ### Example
/// ```
/// # use pqc_kyber::*; 
/// # let mut rng = rand::thread_rng();
/// # let keys = keypair(&mut rng).unwrap();
/// let (ct, ss) = encapsulate(&keys.public, &mut rng).unwrap();
/// ```
pub fn encapsulate<R: CryptoRng + RngCore>(pk: &[u8], rng: &mut R) -> Encapsulated {
  if pk.len() != KYBER_PUBLICKEYBYTES {
    return Err(KyberError::EncodeFail)
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
/// # let mut rng = rand::thread_rng();
/// # let keys = keypair(&mut rng).unwrap();
/// let (ct, ss1) = encapsulate(&keys.public, &mut rng).unwrap();
/// let ss2 = decapsulate(&ct, &keys.secret).unwrap();
/// assert_eq!(ss1, ss2);
/// ```
pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Decapsulated {
  let mut ss = [0u8; KYBER_SSBYTES];
  match api::crypto_kem_dec(&mut ss, ct, sk) {
    Ok(_) => Ok(ss),
    Err(e) => Err(e)
  }
}

/// Contains a public/private keypair
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Keys {
    pub public: PublicKey,
    pub secret: SecretKey
}

impl Default for Keys {
  fn default() -> Self {
    Keys {
      public: [0u8; KYBER_PUBLICKEYBYTES],
      secret: [0u8; KYBER_SECRETKEYBYTES]
    }
  }
}

impl Keys {
  /// Securely generates a new keypair using `rand::thread_rng()`
  /// ```
  /// # use pqc_kyber::*;
  /// let real_keys = Keys::generate().unwrap();
  /// let empty_keys = Keys::default();
  /// assert!(real_keys != empty_keys); 
  /// ```
  pub fn generate() -> Result<Keys, KyberError> {
    let mut rng = rand::thread_rng();
    keypair(&mut rng)
  }
}

