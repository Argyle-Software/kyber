use crate::params::*;

const MONT: usize = 2285; // 2^16 % Q
const QINV: i32 = 62209; // q^(-1) mod 2^16

/*************************************************
* Name:        montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q,
*              where R=2^16
*
* Arguments:   - int32_t a: input integer to be reduced; has to be in {-q2^15,...,q2^15-1}
*
* Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
**************************************************/
pub fn montgomery_reduce(a: i32) -> i16 
{
  let ua = a.wrapping_mul(QINV) as i16;
  let u = ua as i32;
  let mut t = u * KYBER_Q as i32;
  t = a - t;
  t >>= 16;
  t as i16
}

/*************************************************
* Name:        barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              16-bit integer congruent to a mod q in {0,...,q}
*
* Arguments:   - int16_t a: input integer to be reduced
*
* Returns:     integer in {0,...,q} congruent to a modulo q.
**************************************************/
pub fn barrett_reduce(a: i16) -> i16 
{
  let v = ((1u32 << 26)/KYBER_Q as u32 + 1) as i32;
  let mut t = v * a as i32;
  t >>= 26;
  t *= KYBER_Q as i32;
  a - t as i16
}


/*************************************************
* Name:        csubq
*
* Description: Conditionallly subtract q
*
* Arguments:   - int16_t x: input integer
*
* Returns:     a - q if a >= q, else a
**************************************************/
pub fn csubq(mut a: i16) -> i16 
{
  a -= KYBER_Q as i16;
  a += (a >> 15) & KYBER_Q as i16;
  a
}

