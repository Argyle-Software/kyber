// Security Strengths
#[cfg(feature = "kyber512")]
pub const KYBER_K: usize = 2;

/// The algorithm security level
/// 
/// Defaults to 3, will change when kyber512 or kyber1024 is selected.
#[cfg(not(any(feature = "kyber512", feature = "1024")))]
pub const KYBER_K: usize = 3; 

#[cfg(feature = "1024")]
pub const KYBER_K: usize = 4;

/// Whether 90s mode is being used
#[cfg(not(feature = "90s"))]
pub const KYBER_90S: bool = false;

#[cfg(feature = "90s")]
pub const KYBER_90S: bool = true;

pub const KYBER_N: usize = 256;
pub const KYBER_Q: usize = 3329;

#[cfg(feature = "kyber512")]
pub const KYBER_ETA1: usize = 3;
#[cfg(not(feature = "kyber512"))]
pub const KYBER_ETA1: usize = 2;

pub const KYBER_ETA2: usize = 2;

// size in bytes of hashes, and seeds
pub const KYBER_SYMBYTES: usize = 32;
/// Size of the shared key 
pub const KYBER_SSBYTES: usize =  32; 

pub const KYBER_POLYBYTES: usize = 384;
pub const KYBER_POLYVECBYTES: usize =  KYBER_K * KYBER_POLYBYTES;

#[cfg(feature = "512")]
pub const KYBER_POLYCOMPRESSEDBYTES: usize =     96;
#[cfg(feature = "512")]
pub const KYBER_POLYVECCOMPRESSEDBYTES: usize =  KYBER_K * 320;

#[cfg(not(any(feature = "512", feature = "1024")))]
pub const KYBER_POLYCOMPRESSEDBYTES: usize =     128;
#[cfg(not(any(feature = "512", feature = "1024")))]
pub const KYBER_POLYVECCOMPRESSEDBYTES: usize =  KYBER_K * 320;

#[cfg(feature = "1024")]
pub const KYBER_POLYCOMPRESSEDBYTES: usize =     160;
#[cfg(feature = "1024")]
pub const KYBER_POLYVECCOMPRESSEDBYTES: usize = KYBER_K * 352;

// pub const KYBER_INDCPA_MSGBYTES: usize =       KYBER_SYMBYTES;
pub const KYBER_INDCPA_PUBLICKEYBYTES: usize = KYBER_POLYVECBYTES + KYBER_SYMBYTES;
pub const KYBER_INDCPA_SECRETKEYBYTES: usize = KYBER_POLYVECBYTES;
pub const KYBER_INDCPA_BYTES: usize = KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES;

/// Size of the public key
pub const KYBER_PUBLICKEYBYTES: usize = KYBER_INDCPA_PUBLICKEYBYTES;
/// Size of the secret key 
pub const KYBER_SECRETKEYBYTES: usize =  KYBER_INDCPA_SECRETKEYBYTES +  KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES; 
/// Size of the ciphertext
pub const KYBER_CIPHERTEXTBYTES: usize =  KYBER_INDCPA_BYTES;