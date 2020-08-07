// Security Strengths
#[cfg(feature = "512")]
pub const KYBER_K: usize = 2;

#[cfg(not(feature = "512"))]
#[cfg(not(feature = "1024"))]
pub const KYBER_K: usize = 3; 

#[cfg(feature = "1024")]
pub const KYBER_K: usize = 4;

pub const KYBER_N: usize = 256;
pub const KYBER_Q: usize = 3329;

pub const KYBER_ETA: usize = 2;

pub const KYBER_SYMBYTES: usize = 32;   /* size in bytes of hashes, and seeds */
pub const KYBER_SSBYTES: usize =  32;   /* size in bytes of shared key */

pub const KYBER_POLYBYTES: usize = 384;
pub const KYBER_POLYVECBYTES: usize =  KYBER_K * KYBER_POLYBYTES;

#[cfg(feature = "512")]
pub const KYBER_POLYCOMPRESSEDBYTES: usize =     96;
#[cfg(feature = "512")]
pub const KYBER_POLYVECCOMPRESSEDBYTES: usize =  KYBER_K * 320;

#[cfg(not(feature = "512"))]
#[cfg(not(feature = "1024"))]
pub const KYBER_POLYCOMPRESSEDBYTES: usize =     128;
#[cfg(not(feature = "512"))]
#[cfg(not(feature = "1024"))]
pub const KYBER_POLYVECCOMPRESSEDBYTES: usize =  KYBER_K * 320;

#[cfg(feature = "1024")]
pub const KYBER_POLYCOMPRESSEDBYTES: usize =     160;
#[cfg(feature = "1024")]
pub const KYBER_POLYVECCOMPRESSEDBYTES: usize = KYBER_K * 352;

pub const KYBER_INDCPA_MSGBYTES: usize =       KYBER_SYMBYTES;
pub const KYBER_INDCPA_PUBLICKEYBYTES: usize = KYBER_POLYVECBYTES + KYBER_SYMBYTES;
pub const KYBER_INDCPA_SECRETKEYBYTES: usize = KYBER_POLYVECBYTES;
pub const KYBER_INDCPA_BYTES: usize = KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES;

pub const KYBER_PUBLICKEYBYTES: usize = KYBER_INDCPA_PUBLICKEYBYTES;
pub const KYBER_SECRETKEYBYTES: usize =  KYBER_INDCPA_SECRETKEYBYTES +  KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES; /* 32 bytes of additional space to save H(pk) */
pub const KYBER_CIPHERTEXTBYTES: usize =  KYBER_INDCPA_BYTES;