use rand::prelude::*;

pub fn randombytes(x: &mut [u8], xlen: usize)
{
  thread_rng().fill_bytes(&mut x)
}

