#![allow(clippy::precedence)]
use crate::{
  poly::*,
  params::*
};

#[derive(Clone)]
pub struct Polyvec {
  pub vec: [Poly; KYBER_K]
}

impl Copy for Polyvec {}

impl Polyvec {
  pub fn new() -> Self {
    Polyvec {
      vec: [Poly::new(); KYBER_K]
    }
  }
}

// Name:        polyvec_compress
//
// Description: Compress and serialize vector of polynomials
//
// Arguments:   - [u8] r: output byte array (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
//              - const polyvec *a: input vector of polynomials
pub fn polyvec_compress(r: &mut[u8], a: Polyvec)
{
  if KYBER_POLYVECCOMPRESSEDBYTES == KYBER_K * 352 {
    let mut t = [0u16; 8];
    let mut idx = 0usize;
    for i in 0..KYBER_K {
      for j in 0..KYBER_N/8 {
        for k in 0..8 {
          t[k]  = a.vec[i].coeffs[8*j+k] as u16;
          t[k] += (((t[k] as i16) >> 15) & KYBER_Q as i16) as u16;
          t[k]  = (((((t[k] as u32) << 11) + KYBER_Q as u32/2)/KYBER_Q as u32) & 0x7ff ) as u16;
        }
        r[idx+0] = (t[0] >>  0) as u8;
        r[idx+1] = ((t[0] >>  8) | (t[1] << 3)) as u8;
        r[idx+2] = ((t[1] >>  5) | (t[2] << 6)) as u8;
        r[idx+3] = (t[2] >>  2) as u8;
        r[idx+4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
        r[idx+5] = ((t[3] >>  7) | (t[4] << 4)) as u8;
        r[idx+6] = ((t[4] >>  4) | (t[5] << 7)) as u8;
        r[idx+7] = (t[5] >>  1) as u8;
        r[idx+8] = ((t[5] >>  9) | (t[6] << 2)) as u8;
        r[idx+9] = ((t[6] >>  6) | (t[7] << 5)) as u8;
        r[idx+10] = (t[7] >>  3) as u8;
        idx += 11
      }
    }
  } else if KYBER_POLYVECCOMPRESSEDBYTES == KYBER_K * 320 {
    let mut t = [0u16; 4];
    let mut idx = 0usize;
    for i in 0..KYBER_K {
      for j in 0..KYBER_N/4 {
        for k in 0..4 {
          t[k]  = a.vec[i].coeffs[4*j+k] as u16;
          t[k] = t[k].wrapping_add((((t[k] as i16) >> 15) & KYBER_Q as i16) as u16);
          t[k]  = (((((t[k] as u32) << 10) + KYBER_Q as u32/2)/ KYBER_Q as u32) & 0x3ff) as u16;
        }
        r[idx+0] = (t[0] >> 0) as u8;
        r[idx+1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
        r[idx+2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
        r[idx+3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
        r[idx+4] = (t[3] >> 2) as u8;
        idx += 5;
      }
    }
  } else {
    panic!("KYBER_POLYVECCOMPRESSEDBYTES needs to be in (320*KYBER_K, 352*KYBER_K)");
  }
}

// Name:        polyvec_decompress
//
// Description: De-serialize and decompress vector of polynomials;
//              approximate inverse of polyvec_compress
//
// Arguments:   - polyvec *r:       output vector of polynomials
//              - [u8] a: input byte array (of length KYBER_POLYVECCOMPRESSEDBYTES)
pub fn polyvec_decompress(r: &mut Polyvec, a: &[u8]) 
{
  // TODO: use conditional compilation flags instead
  if KYBER_POLYVECCOMPRESSEDBYTES == KYBER_K * 352 {
    let mut t = [0u16; 8];
    let mut idx = 0usize;
    for i in 0..KYBER_K {
      for j in 0..KYBER_N/8 {
        t[0] = (a[idx+0] >> 0) as u16 | (a[idx+ 1] as u16) << 8;
        t[1] = (a[idx+1] >> 3) as u16 | (a[idx+ 2] as u16) << 5;
        t[2] = (a[idx+2] >> 6) as u16 | (a[idx+ 3] as u16 ) << 2 | (a[idx+4] as u16) << 10;
        t[3] = (a[idx+4] >> 1) as u16 | (a[idx+ 5] as u16) << 7;
        t[4] = (a[idx+5] >> 4) as u16 | (a[idx+ 6] as u16) << 4;
        t[5] = (a[idx+6] >> 7) as u16 | (a[idx+ 7] as u16) << 1 | (a[idx+8] as u16) << 9;
        t[6] = (a[idx+8] >> 2) as u16 | (a[idx+ 9] as u16) << 6;
        t[7] = (a[idx+9] >> 5) as u16 | (a[idx+10] as u16) << 3;
        idx += 11;

        for k in 0..8 {
          r.vec[i].coeffs[8*j+k] = (((t[k] & 0x7FF)as u32 * KYBER_Q as u32 + 1024) >> 11) as i16;
        }
      }
    }
  } else if KYBER_POLYVECCOMPRESSEDBYTES == KYBER_K * 320 {
    let mut idx = 0usize;
    let mut t = [0u16; 4];
    for i in 0..KYBER_K {
      for j in 0..KYBER_N/4 {
        t[0] = (a[idx+0] >> 0) as u16 | (a[idx+1] as u16) << 8;
        t[1] = (a[idx+1] >> 2) as u16 | (a[idx+2] as u16) << 6;
        t[2] = (a[idx+2] >> 4) as u16 | (a[idx+3] as u16) << 4;
        t[3] = (a[idx+3] >> 6) as u16 | (a[idx+4] as u16) << 2;
        idx += 5;

        for k in 0..4 {
          r.vec[i].coeffs[4*j+k] = ((((t[k] as u32) & 0x3FF) * KYBER_Q as u32  + 512) >> 10) as i16;
        }
      }
    }
  } else {
    panic!("KYBER_POLYVECCOMPRESSEDBYTES needs to be in (320*KYBER_K, 352*KYBER_K)");
  } 
}

// Name:        polyvec_tobytes
//
// Description: Serialize vector of polynomials
//
// Arguments:   - [u8] r: output byte array (needs space for KYBER_POLYVECBYTES)
//              - const polyvec *a: input vector of polynomials 
pub fn polyvec_tobytes(r: &mut[u8], a: &mut Polyvec)
{
  // TODO: No need for mutable poly ref  - poly.rs polyvec.rs - toindcpa.rs 
  for i in 0..KYBER_K {
    poly_tobytes(&mut r[i*KYBER_POLYBYTES..], a.vec[i]);
  }
}

// Name:        polyvec_frombytes
//
// Description: De-serialize vector of polynomials;
//              inverse of polyvec_tobytes
//
// Arguments:   - [u8] r: output byte array
//              - const polyvec *a: input vector of polynomials (of length KYBER_POLYVECBYTES)
pub fn polyvec_frombytes(r: &mut Polyvec, a: &[u8])
{
  for i in 0..KYBER_K {
    poly_frombytes(&mut r.vec[i], &a[i*KYBER_POLYBYTES..]);
  }
}

// Name:        polyvec_ntt
//
// Description: Apply forward NTT to all elements of a vector of polynomials
//
// Arguments:   - polyvec *r: in/output vector of polynomials
pub fn polyvec_ntt(r: &mut Polyvec)
{
  for i in 0..KYBER_K {
    poly_ntt(&mut r.vec[i]);
  }
}

// Name:        polyvec_invntt
//
// Description: Apply inverse NTT to all elements of a vector of polynomials
//
// Arguments:   - polyvec *r: in/output vector of polynomials
pub fn polyvec_invntt(r: &mut Polyvec)
{
  for i in 0..KYBER_K {
    poly_invntt(&mut r.vec[i]);
  }
}

// Name:        polyvec_basemul_acc_montgomery
//
// Description: Pointwise multiply elements of a and b and accumulate into r
//
// Arguments: - poly *r:          output polynomial
//            - const polyvec *a: first input vector of polynomials
//            - const polyvec *b: second input vector of polynomials
pub fn polyvec_basemul_acc_montgomery(r: &mut Poly, a: &Polyvec, b: &Polyvec)
{
  let mut t = Poly::new();
  poly_basemul(r, &a.vec[0], &b.vec[0]);
  for i in 1..KYBER_K {
    poly_basemul(&mut t, &a.vec[i], &b.vec[i]);
    poly_add(r, &t);
  }
  poly_reduce(r);
}

// Name:        polyvec_reduce
//
// Description: Applies Barrett reduction to each coefficient 
//              of each element of a vector of polynomials
//              for details of the Barrett reduction see comments in reduce.c
//
// Arguments:   - poly *r:       input/output polynomial
pub fn polyvec_reduce(r: &mut Polyvec)
{
 for i in 0..KYBER_K {
  poly_reduce(&mut r.vec[i]);
 } 
}


// Name:        polyvec_add
//
// Description: Add vectors of polynomials
//
// Arguments: - polyvec *r:       output vector of polynomials
//            - const polyvec *a: first input vector of polynomials
//            - const polyvec *b: second input vector of polynomials
pub fn polyvec_add(r: &mut Polyvec, b: &Polyvec)
{
  for i in 0..KYBER_K {
    poly_add(&mut r.vec[i], &b.vec[i]);
  }
}
