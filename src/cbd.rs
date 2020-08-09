use crate::poly::Poly;
use crate::params::{KYBER_ETA, KYBER_N};


// Name:        load32_littleendian
//
// Description: load bytes into a 32-bit integer
//              in little-endian order
//
// Arguments:   - const unsigned char *x: pointer to input byte array
//
// Returns 32-bit unsigned integer loaded from x
fn load32_littleendian(x: &[u8]) -> u32 
{
  let mut r = x[0] as u32;
  r |= (x[1] as u32) << 8;
  r |= (x[2] as u32)  << 16;
  r |= (x[3] as u32) << 24;
  r
}


// Name:        cbd
//
// Description: Given an array of uniformly random bytes, compute
//              polynomial with coefficients distributed according to
//              a centered binomial distribution with parameter KYBER_ETA
//
// Arguments:   - poly *r:                  pointer to output polynomial
//              - const unsigned char *buf: pointer to input byte array
pub fn cbd(r: &mut Poly, buf: &[u8])
{
  let (mut d, mut t, mut a, mut b); 
  if KYBER_ETA == 2 {
    for i in 0..(KYBER_N/8) {
      t = load32_littleendian(&buf[4*i..]);
      d  = t & 0x55555555;
      d += (t>>1) & 0x55555555;
      for j in 0..8 {
        a = ((d >>  (4*j))    & 0x3) as i16;
        b = ((d >> (4*j+2)) & 0x3) as i16;
        r.coeffs[8*i+j] = a - b;
      }
    }
  }
}
