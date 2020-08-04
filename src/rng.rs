use rand::prelude::*;

pub fn randombytes(x: &mut [u8])
{
  thread_rng().fill_bytes(x)
}

