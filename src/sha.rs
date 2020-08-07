// Conditional 90s version
// use sha2::{Sha256, Sha512, Digest};
use crate::fips202::{sha3_256, sha3_512};

// TODO: check if nlen parameter can be removed
pub fn sha256(out: &mut[u8], input: &[u8], inlen: usize)
{

  sha3_256(out, input, inlen);
  // TODO: Add 90s version conditional compilation
  // Uses sha2 below
  // let mut hasher = Sha256::new();
  // hasher.update(&input[..inlen]);
  // out.copy_from_slice(&hasher.finalize())
}


pub fn sha512(out: &mut[u8], input: &[u8], inlen: usize)
{
  sha3_512(out, input, inlen);
  // let mut hasher = Sha512::new();
  // hasher.update(&input[..inlen]);
  // out.copy_from_slice(&hasher.finalize())
}

