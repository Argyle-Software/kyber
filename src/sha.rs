use sha2::{Sha256, Sha512, Digest};

pub fn sha256(out: &mut[u8], input: &[u8], inlen: usize)
{
  let mut hasher = Sha256::new();
  hasher.update(input);
  out.clone_from_slice(&hasher.finalize())
}


pub fn sha512(out: &mut[u8], input: &[u8], inlen: usize)
{
  let mut hasher = Sha512::new();
  hasher.update(input);
  out.clone_from_slice(&hasher.finalize())
}

