// Security Strengths
#[cfg(feature = "kyber512")]
pub const KYBER_K: usize = 2;

/// The security level of Kyber
/// 
/// Defaults to 3 (kyber768), will be 2 or 4 repsectively when 
/// kyber512 or kyber1024 are selected.
#[cfg(not(any(feature = "kyber512", feature = "kyber1024")))]
pub const KYBER_K: usize = 3; 

#[cfg(feature = "kyber1024")]
pub const KYBER_K: usize = 4;

/// A boolean flag for whether 90s mode is activated
/// 
/// In 90s mode AES-CTR and SHA256 primitives are used instead
/// which in some instances can be useful for hardware supported
/// improvements.
/// 
/// Defaults to false, set`features = ["90s"]` to use. 
#[cfg(not(feature = "90s"))]
pub const KYBER_90S: bool = false;
#[cfg(feature = "90s")]
pub const KYBER_90S: bool = true;


pub(crate) const KYBER_N: usize = 256;
pub(crate) const KYBER_Q: usize = 3329;

#[cfg(feature = "kyber512")]
pub(crate) const KYBER_ETA1: usize = 3;
#[cfg(not(feature = "kyber512"))]
pub(crate) const KYBER_ETA1: usize = 2;
pub(crate) const KYBER_ETA2: usize = 2;

// size in bytes of hashes, and seeds
pub(crate) const KYBER_SYMBYTES: usize = 32;
/// Size of the shared key 
pub const KYBER_SSBYTES: usize =  32; 

pub(crate) const KYBER_POLYBYTES: usize = 384;
pub(crate) const KYBER_POLYVECBYTES: usize =  KYBER_K * KYBER_POLYBYTES;

#[cfg(feature = "kyber512")]
pub(crate) const KYBER_POLYCOMPRESSEDBYTES: usize =     128;

#[cfg(feature = "kyber512")]
pub(crate) const KYBER_POLYVECCOMPRESSEDBYTES: usize =  KYBER_K * 320;

#[cfg(not(any(feature = "kyber512", feature = "kyber1024")))]
pub(crate) const KYBER_POLYCOMPRESSEDBYTES: usize =     128;
#[cfg(not(any(feature = "kyber512", feature = "kyber1024")))]
pub(crate) const KYBER_POLYVECCOMPRESSEDBYTES: usize =  KYBER_K * 320;

#[cfg(feature = "kyber1024")]
pub(crate) const KYBER_POLYCOMPRESSEDBYTES: usize =     160;
#[cfg(feature = "kyber1024")]
pub(crate) const KYBER_POLYVECCOMPRESSEDBYTES: usize = KYBER_K * 352;

pub(crate) const KYBER_INDCPA_PUBLICKEYBYTES: usize = KYBER_POLYVECBYTES + KYBER_SYMBYTES;
pub(crate) const KYBER_INDCPA_SECRETKEYBYTES: usize = KYBER_POLYVECBYTES;
pub(crate) const KYBER_INDCPA_BYTES: usize = KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES;

/// Size of the public key
pub const KYBER_PUBLICKEYBYTES: usize = KYBER_INDCPA_PUBLICKEYBYTES;
/// Size of the secret key 
pub const KYBER_SECRETKEYBYTES: usize =  KYBER_INDCPA_SECRETKEYBYTES +  KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES; 
/// Size of the ciphertext
pub const KYBER_CIPHERTEXTBYTES: usize =  KYBER_INDCPA_BYTES;