use core::arch::x86_64::*;
use crate::params::*;
use crate::poly::NOISE_NBLOCKS;
use crate::fips202::{SHAKE128_RATE, SHAKE256_RATE};
// use crate::symmetric::AES256CTR_BLOCKBYTES;
use crate::avx2::rejsample::REJ_UNIFORM_AVX_NBLOCKS;

// Buffer unions
#[derive(Copy, Clone)]
#[repr(C, align(32))]
pub union GenMatrixBuf {
  pub coeffs: [u8; REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE],
  pub vec: [__m256i; (REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE+31)/32]
}

impl GenMatrixBuf {
  pub fn new() -> Self {
    Self { coeffs: [0u8; REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE]}
  }
}

// #[repr(C)]
// pub union GenMatrixBuf90s {
//   pub coeffs: 
//     [u8; REJ_UNIFORM_AVX_NBLOCKS*AES256CTR_BLOCKBYTES],
//   pub vec: 
//     [__m256i; (REJ_UNIFORM_AVX_NBLOCKS*AES256CTR_BLOCKBYTES+31)/32]
// }

// impl GenMatrixBuf90s {
//   pub fn new() -> Self {
//     Self { 
//       coeffs: [0u8; REJ_UNIFORM_AVX_NBLOCKS*AES256CTR_BLOCKBYTES]
//     }
//   }
// }

// #[repr(C)]
// pub union IndcpaBuf {
//   pub coeffs: [u8; 
//   (KYBER_ETA1*KYBER_N/4)
//   /AES256CTR_BLOCKBYTES*AES256CTR_BLOCKBYTES+32],
//   pub vec: [__m256i; 
//   ((KYBER_ETA1*KYBER_N/4)
//   /AES256CTR_BLOCKBYTES*AES256CTR_BLOCKBYTES+32+31)/32]
// }

// impl IndcpaBuf {
//   pub fn new() -> Self {
//     Self { 
//       coeffs: [0u8; 
//       (KYBER_ETA1*KYBER_N/4)
//       /AES256CTR_BLOCKBYTES*AES256CTR_BLOCKBYTES+32]
//     }
//   }
// }


// TODO: Redundant
// #[repr(C, align(8))]
// pub union Eta1Buf {
//   pub coeffs: [u8; KYBER_ETA1*KYBER_N/4+32],
//   pub vec: [__m256i; (KYBER_ETA1*KYBER_N/4+32+31)/32]
// }

// impl Eta1Buf {
//   pub fn new() -> Self {
//     Self { coeffs: [0u8; KYBER_ETA1*KYBER_N/4+32] }
//   }
// }

#[repr(C, align(8))]
pub union Eta2Buf {
  pub coeffs: [u8; KYBER_ETA2*KYBER_N/4],
  pub vec: [__m256i; (KYBER_ETA2*KYBER_N/4+31)/32]
}

impl Eta2Buf {
  pub fn new() -> Self {
    Self { coeffs: [0u8; KYBER_ETA2*KYBER_N/4] }
  }
}

#[derive(Copy, Clone)]
#[repr(C, align(8))]
pub union Eta4xBuf {
  pub coeffs: [u8; NOISE_NBLOCKS*SHAKE256_RATE],
  pub vec: [__m256i; (NOISE_NBLOCKS*SHAKE256_RATE+31)/32]
}

impl Eta4xBuf {
  pub fn new() -> Self {
    Self { coeffs: [0u8; NOISE_NBLOCKS*SHAKE256_RATE] }
  }
}

