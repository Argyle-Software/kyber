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

/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - unsigned char *r: pointer to output byte array (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
pub fn polyvec_compress(r: &mut[u8], a: &mut Polyvec)
{
  polyvec_csubq(a);

  if KYBER_POLYVECCOMPRESSEDBYTES == KYBER_K * 352 {
    let mut t = [0u16; 8];
    let mut idx = 0usize;
    for i in 0..KYBER_K {
      for j in 0..KYBER_N/8 {
        for k in 0..8 {
          t[k] = (((((a.vec[i].coeffs[8*j+k] as u32) << 11) + KYBER_Q as u32/2) / KYBER_Q as u32) & 0x7ff) as u16;
        }
        r[idx+11*j   ] =  (t[0] & 0xff) as u8;
        r[idx+11*j+ 1] = ((t[0] >>  8) | ((t[1] & 0x1f) << 3)) as u8;
        r[idx+11*j+ 2] = ((t[1] >>  5) | ((t[2] & 0x03) << 6)) as u8;
        r[idx+11*j+ 3] = ((t[2] >>  2) & 0xff) as u8;
        r[idx+11*j+ 4] = ((t[2] >> 10) | ((t[3] & 0x7f) << 1)) as u8;
        r[idx+11*j+ 5] = ((t[3] >>  7) | ((t[4] & 0x0f) << 4)) as u8;
        r[idx+11*j+ 6] = ((t[4] >>  4) | ((t[5] & 0x01) << 7)) as u8;
        r[idx+11*j+ 7] = ((t[5] >>  1) & 0xff) as u8;
        r[idx+11*j+ 8] = ((t[5] >>  9) | ((t[6] & 0x3f) << 2)) as u8;
        r[idx+11*j+ 9] = ((t[6] >>  6) | ((t[7] & 0x07) << 5)) as u8;
        r[idx+11*j+10] = (t[7] >>  3) as u8;
      }
      // TODO: Confirm indexing is correct
      idx += 352;
    }
  } else if KYBER_POLYVECCOMPRESSEDBYTES == KYBER_K * 320 {
    let mut t = [0u16; 4];
    let mut idx = 0usize;
    for i in 0..KYBER_K {
      for j in 0..KYBER_N/4 {
        for k in 0..4 {
          t[k] = (((((a.vec[i].coeffs[4*j+k] as u32) << 10) + KYBER_Q as u32/2) / KYBER_Q as u32) & 0x3ff) as u16;
        }
        r[idx+5*j   ] =  (t[0] & 0xff) as u8;
        r[idx+5*j+ 1] = ((t[0] >>  8) | ((t[1] & 0x3f) << 2)) as u8;
        r[idx+5*j+ 2] = ((t[1] >>  6) | ((t[2] & 0x0f) << 4)) as u8;
        r[idx+5*j+ 3] = ((t[2] >>  4) | ((t[3] & 0x03) << 6)) as u8;
        r[idx+5*j+ 4] = (t[3] >>  2) as u8;
      }
      // TODO: Confirm indexing is correct
      idx += 320;
    }
  } else {
    panic!("KYBER_POLYVECCOMPRESSEDBYTES needs to be in (320*KYBER_K, 352*KYBER_K)");
  }
}


/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress
*
* Arguments:   - polyvec *r:       pointer to output vector of polynomials
*              - unsigned char *a: pointer to input byte array (of length KYBER_POLYVECCOMPRESSEDBYTES)
**************************************************/
pub fn polyvec_decompress(r: &mut Polyvec, a: &[u8]) 
{
  if KYBER_POLYVECCOMPRESSEDBYTES == KYBER_K * 352 {
    let mut idx = 0usize;
    for i in 0..KYBER_K {
      for j in 0..KYBER_N/8 {
        r.vec[i].coeffs[8*j  ] = ((((a[idx+11*j    ] as u32        | (((a[idx+11*j+ 1] & 0x07) as u32) << 8)) * KYBER_Q as u32) + 1024) >> 11) as i16;
        r.vec[i].coeffs[8*j+1] = (((((a[idx+11*j+ 1] >> 3) as u32 | (((a[idx+11*j+ 2] & 0x3f) as u32) << 5)) * KYBER_Q as u32) + 1024) >> 11) as i16;
        r.vec[i].coeffs[8*j+2] = (((((a[idx+11*j+ 2] >> 6) as u32 | (((a[idx+11*j+ 3] & 0xff) as u32) << 2)) | (((a[idx+11*j+ 4] as u32 & 0x01) << 10)) * KYBER_Q as u32) + 1024) >> 11) as i16;
        r.vec[i].coeffs[8*j+3] = (((((a[idx+11*j+ 4] >> 1) as u32 | (((a[idx+11*j+ 5] & 0x0f) as u32) << 7)) * KYBER_Q as u32) + 1024) >> 11) as i16;
        r.vec[i].coeffs[8*j+4] = (((((a[idx+11*j+ 5] >> 4) as u32 | (((a[idx+11*j+ 6] & 0x7f) as u32) << 4)) * KYBER_Q as u32) + 1024) >> 11) as i16;
        r.vec[i].coeffs[8*j+5] = (((((a[idx+11*j+ 6] >> 7) as u32 | (((a[idx+11*j+ 7] & 0xff) as u32) << 1)) | (((a[idx+11*j+ 8] as u32 & 0x03) <<  9)) * KYBER_Q as u32) + 1024) >> 11) as i16;
        r.vec[i].coeffs[8*j+6] = (((((a[idx+11*j+ 8] >> 2) as u32 | (((a[idx+11*j+ 9] & 0x1f) as u32) << 6)) * KYBER_Q as u32) + 1024) >> 11) as i16;
        r.vec[i].coeffs[8*j+7] = (((((a[idx+11*j+ 9] >> 5) as u32 | (((a[idx+11*j+10] & 0xff) as u32) << 3)) * KYBER_Q as u32) + 1024) >> 11) as i16;
      }
    // TODO: Confirm indexing is correct
    idx += 352;
    }
  } else if KYBER_POLYVECCOMPRESSEDBYTES == KYBER_K * 320 {
    let t = [0u16; 4];
    let mut idx = 0usize;
    for i in 0..KYBER_K {
      for j in 0..KYBER_N/4 {
        r.vec[i].coeffs[4*j  ] =  ((((a[idx+5*j  ] as u32       | (((a[idx+5*j+1] & 0x03) as u32) << 8)) * KYBER_Q as u32) + 512) >> 10) as i16;
        r.vec[i].coeffs[4*j+1] = (((((a[idx+5*j+1] >> 2) as u32 | (((a[idx+5*j+2] & 0x0f) as u32) << 6)) * KYBER_Q as u32) + 512) >> 10) as i16;
        r.vec[i].coeffs[4*j+2] = (((((a[idx+5*j+2] >> 4) as u32 | (((a[idx+5*j+3] & 0x3f) as u32) << 4)) * KYBER_Q as u32) + 512) >> 10) as i16;
        r.vec[i].coeffs[4*j+3] = (((((a[idx+5*j+3] >> 6) as u32 | (((a[idx+5*j+4] & 0xff) as u32) << 2)) * KYBER_Q as u32) + 512) >> 10) as i16;
      }
      // TODO: Confirm indexing is correct
      idx += 320;
    }
  } else {
    panic!("KYBER_POLYVECCOMPRESSEDBYTES needs to be in (320*KYBER_K, 352*KYBER_K)");
  } 
}


/*************************************************
* Name:        polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - unsigned char *r: pointer to output byte array (needs space for KYBER_POLYVECBYTES)
*              - const polyvec *a: pointer to input vector of polynomials 
**************************************************/
pub fn polyvec_tobytes(r: &mut[u8], a: &mut Polyvec)
{
  // TODO: No need for mutable poly ref  - poly.rs polyvec.rs - toindcpa.rs 
  for i in 0..KYBER_K {
    poly_tobytes(&mut r[i*KYBER_POLYBYTES..], &mut a.vec[i]);
  }
}


/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials (of length KYBER_POLYVECBYTES)
**************************************************/
pub fn polyvec_frombytes(r: &mut Polyvec, a: &[u8])
{
  for i in 0..KYBER_K {
    poly_frombytes(&mut r.vec[i], &a[i*KYBER_POLYBYTES..]);
  }
}


/*************************************************
* Name:        polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
pub fn polyvec_ntt(r: &mut Polyvec)
{
  for i in 0..KYBER_K {
    poly_ntt(&mut r.vec[i]);
  }
}


/*************************************************
* Name:        polyvec_invntt
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
pub fn polyvec_invntt(r: &mut Polyvec)
{
  for i in 0..KYBER_K {
    poly_invntt(&mut r.vec[i]);
  }
}


/*************************************************
* Name:        polyvec_pointwise_acc
*
* Description: Pointwise multiply elements of a and b and accumulate into r
*
* Arguments: - poly *r:          pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
pub fn polyvec_pointwise_acc(r: &mut Poly, a: &Polyvec, b: &Polyvec)
{
  let mut t = Poly::new();
  poly_basemul(r, &a.vec[0], &b.vec[0]);
  for i in 0..KYBER_K {
    poly_basemul(&mut t, &a.vec[i], &b.vec[i]);
    poly_add(r, &t);
  }
  poly_reduce(r);
}


/*************************************************
* Name:        polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient 
*              of each element of a vector of polynomials
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r:       pointer to input/output polynomial
**************************************************/
pub fn polyvec_reduce(r: &mut Polyvec)
{
 for i in 0..KYBER_K {
  poly_reduce(&mut r.vec[i]);
 } 
}


/*************************************************
* Name:        polyvec_csubq
*
* Description: Applies conditional subtraction of q to each coefficient 
*              of each element of a vector of polynomials
*              for details of conditional subtraction of q see comments in reduce.c
*
* Arguments:   - poly *r:       pointer to input/output polynomial
**************************************************/
pub fn polyvec_csubq(r: &mut Polyvec)
{
  for i in 0..KYBER_K{
    poly_csubq(&mut r.vec[i]);
  }
}


/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r:       pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
pub fn polyvec_add(r: &mut Polyvec, b: &Polyvec)
{
  for i in 0..KYBER_K {
    poly_add(&mut r.vec[i], &b.vec[i]);
  }
}
