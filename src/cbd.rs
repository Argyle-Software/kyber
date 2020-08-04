use crate::poly::*;
use crate::params::{KYBER_ETA, KYBER_N};
use std::num::Wrapping;

/*************************************************
* Name:        load32_littleendian
*
* Description: load bytes into a 32-bit integer
*              in little-endian order
*
* Arguments:   - const unsigned char *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x
**************************************************/

pub fn load32_littleendian(x: &[u8]) -> u32 
{
  let mut r = Wrapping(x[0]);
  r |= Wrapping(x[1]) << 8;
  r |= Wrapping(x[2]) << 16;
  r |= Wrapping(x[3]) << 24;
  r.0 as u32 
}

/*************************************************
* Name:        cbd
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter KYBER_ETA
*
* Arguments:   - poly *r:                  pointer to output polynomial
*              - const unsigned char *buf: pointer to input byte array
**************************************************/

pub fn cbd(r: &mut Poly, buf: &[u8])
{
  let (mut d, mut t, mut a, mut b) =  (0u32, 0u32, 0i16, 0i16); 
  if KYBER_ETA == 2 {
    for i in 0..(KYBER_N/8) {
      t = load32_littleendian(&buf[4*i..]);
      d  = t & 0x55555555;
      d += (t>>1) & 0x55555555;
      for j in 0..8 {
        a = ((d >>  4*j)    & 0x3) as i16;
        b = ((d >> (4*j+2)) & 0x3) as i16;
        r.coeffs[8*i+j] = a - b;
      }
    }
  }
}