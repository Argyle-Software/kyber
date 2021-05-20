use rand_core::{RngCore, CryptoRng};
use crate::{
  kem::*,
  symmetric::kdf,
  params::*,
  KyberError
};

/// Unilateral key exchange send A size
pub const KEX_UAKE_SENDABYTES: usize = KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES;
/// Unilateral key exchange send B size
pub const KEX_UAKE_SENDBBYTES: usize = KYBER_CIPHERTEXTBYTES;
/// Key exchange send A size
pub const KEX_AKE_SENDABYTES: usize = KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES;
/// Key exchange send B size
pub const KEX_AKE_SENDBBYTES: usize = 2 * KYBER_CIPHERTEXTBYTES;
/// Key exchange shared key size
pub const KEX_SSBYTES: usize = KYBER_SSBYTES;

/// Result of encapsulating a public key which includes the ciphertext and shared secret
pub type Encapsulated =  Result<([u8; KYBER_CIPHERTEXTBYTES], [u8; KYBER_SSBYTES]), KyberError>;
/// The result of  decapsulating a ciphertext which produces a shared secret when confirmed
pub type Decapsulated = Result<[u8; KYBER_SSBYTES], KyberError>;
/// Kyber public key
pub type PublicKey = [u8; KYBER_PUBLICKEYBYTES];
/// Kyber secret key
pub type SecretKey = [u8; KYBER_SECRETKEYBYTES];
/// Kyber Shared Secret
pub type SharedSecret = [u8; KYBER_SSBYTES]; 
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
  /// # use pqc_kyber::Uake;
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
  /// let mut alice = Uake::new();
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
  /// let server_send = bob.server_receive(client_init, &bob_keys.secret, &mut rng)?;
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
  /// # let bob_keys = Keypair::generate(&mut rng)?;
  /// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
  /// let server_send = bob.server_receive(client_init, &bob_keys.secret, &mut rng)?;
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
  /// # use pqc_kyber::Ake;
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
  /// let mut alice = Ake::new();
  /// let bob_keys = Keypair::generate(&mut rng)?;
  /// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
  /// # Ok(()) }
  /// ```
  pub fn client_init<R>(&mut self, pubkey: &PublicKey, rng: &mut R) 
  -> Result<AkeSendA, KyberError>
    where R: CryptoRng + RngCore
  {
    ake_init_a(
      &mut self.send_a, &mut self.temp_key, 
      &mut self.eska, pubkey, rng
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
  /// let alice_keys = Keypair::generate(&mut rng)?;
  /// let bob_keys = Keypair::generate(&mut rng)?;
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
  /// let alice_keys = Keypair::generate(&mut rng)?;
  /// let bob_keys = Keypair::generate(&mut rng)?;
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


/// Unilaterally Authenticated Key Exchange initiation
fn uake_init_a<R>(
  send: &mut[u8], 
  tk: &mut[u8], 
  sk: &mut[u8], 
  pkb: &[u8],
  rng: &mut R
) -> Result<(), KyberError>
  where R: CryptoRng + RngCore
{
  crypto_kem_keypair(send, sk, rng, None);
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
  kdf(k, &buf, 2*KYBER_SYMBYTES);
  Ok(())
}

/// Unilaterally authenticated key exchange computation by Alice
fn uake_shared_a(
  k: &mut[u8], 
  recv: &[u8], 
  tk: &[u8], 
  sk: &[u8]
) -> Result<(), KyberError> 
{
  let mut buf = [0u8; 2*KYBER_SYMBYTES];
  crypto_kem_dec(&mut buf, recv, sk)?;
  buf[KYBER_SYMBYTES..].copy_from_slice(&tk[..]);
  kdf(k, &buf, 2*KYBER_SYMBYTES);
  Ok(())
}

/// Authenticated key exchange initiation by Alice
fn ake_init_a<R>(
  send: &mut[u8], 
  tk: &mut[u8], 
  sk: &mut[u8], 
  pkb: &[u8],
  rng: &mut R
) -> Result<(), KyberError>
  where R: CryptoRng + RngCore
{
  crypto_kem_keypair(send, sk, rng, None);
  crypto_kem_enc(&mut send[KYBER_PUBLICKEYBYTES..], tk, pkb, rng, None)?;
  Ok(())
}

/// Mutually authenticated key exchange computation by Bob
fn ake_shared_b<R>(
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
  kdf(k, &buf, 3*KYBER_SYMBYTES);
  Ok(())
}

/// Mutually authenticated key exchange computation by Alice
fn ake_shared_a(
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
  kdf(k, &buf, 3*KYBER_SYMBYTES);
  Ok(())
}