#include <arm_neon.h>
#include "params.h"
#include "reduce.h"
#include "neon_ntt.h"
#include "poly.h"
#include "polyvec.h"

#define _V (((1U << 26) + KYBER_Q / 2) / KYBER_Q)

/*************************************************
* Name:        neon_polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void neon_polyvec_ntt(polyvec *r)
{
  unsigned int i;
  for (i = 0; i < KYBER_K; i++)
  {
    neon_poly_ntt(&r->vec[i]);
  }
}

/*************************************************
* Name:        neon_polyvec_invntt_to_mont
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void neon_polyvec_invntt_to_mont(polyvec *r)
{
  unsigned int i;
  for (i = 0; i < KYBER_K; i++)
    neon_poly_invntt_tomont(&r->vec[i]);
}

/*************************************************
* Name:        neon_polyvec_add_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments: - polyvec *r:       pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void neon_polyvec_add_reduce(polyvec *c, const polyvec *a)
{
  unsigned int i;
  for (i = 0; i < KYBER_K; i++)
  {
    // c = c + a;
    // c = reduce(c);
    neon_poly_add_reduce(&c->vec[i], &a->vec[i]);
  }
}

/**********************************/
// Load int16x8_t c <= ptr*
#define vload4(c, ptr) c = vld4q_s16(ptr);

// Store *ptr <= c
#define vstore4(ptr, c) vst4q_s16(ptr, c);

// c (int16x8) = a + b (int16x8)
#define vadd8(c, a, b) c = vaddq_s16(a, b);

// c (int16x8) = a - b (int16x8)
#define vsub8(c, a, b) c = vsubq_s16(a, b);

/*************************************************
* Name:        fqmul
*
* Description: Multiplication followed by Montgomery reduction
*
* Arguments:   - int16_t a: first factor
*              - int16_t b: second factor
*
* Returns 16-bit integer congruent to a*b*R^{-1} mod q

out, in: int16x8_t
zeta: input : int16x8_t
t : int16x8x4_t
neon_qinv: const   : int16x8_t
neon_kyberq: const : int16x8_t
rewrite pseudo code:
int16_t fqmul(int16_t b, int16_t c) {
  int32_t t, u, a;

  a = (int32_t) b*c;
  (a_L, a_H) = a
  a_L = a_L * QINV;
  t = a_L * Q;
  (t_L, t_H) = t;
  return t_H - a_H;
}
*************************************************/
#define fqmul(out, in, zeta, t)                                                                              \
  t.val[0] = (int16x8_t)vmull_s16(vget_low_s16(in), vget_low_s16(zeta));                                     \
  t.val[1] = (int16x8_t)vmull_high_s16(in, zeta);                                                            \
  t.val[2] = vuzp1q_s16(t.val[0], t.val[1]);                                          /* a_L  */             \
  t.val[3] = vuzp2q_s16(t.val[0], t.val[1]);                                          /* a_H  */             \
  t.val[0] = vmulq_s16(t.val[2], neon_qinv);                                          /* a_L = a_L * QINV */ \
  t.val[1] = (int16x8_t)vmull_s16(vget_low_s16(t.val[0]), vget_low_s16(neon_kyberq)); /* t_L = a_L * Q */    \
  t.val[2] = (int16x8_t)vmull_high_s16(t.val[0], neon_kyberq);                        /* t_H = a_L * Q*/     \
  t.val[0] = vuzp2q_s16(t.val[1], t.val[2]);                                          /* t_H */              \
  out = vsubq_s16(t.val[3], t.val[0]);                                                /* t_H - a_H */

/*
inout: int16x4_t
t32 : int32x4_t
t16: int16x4_t
neon_v: int16x4_t
neon_kyberq16: inout int16x4_t

int16_t barrett_reduce(int16_t a) {
  int16_t t;
  const int16_t v = ((1U << 26) + KYBER_Q / 2) / KYBER_Q;

  t = (int32_t)v * a;
  (t_L, t_H) = t; 
  t_h = t_H + (1 << 9);
  t_H = t_H >> 10;
  t_H = a - t_H * KYBER_Q;
  return t_H;
}
*/

/*
reduce low and high of 
inout: 
int16x8_t inout, 
t32_1, t32_2: int32x4_t 
t16: int16x8_t 
neon_v, neon_kyber16
*/
#define barrett(inout, t, i)                                                  \
  t.val[i] = (int16x8_t)vmull_s16(vget_low_s16(inout), vget_low_s16(neon_v)); \
  t.val[i + 1] = (int16x8_t)vmull_high_s16(inout, neon_v);                    \
  t.val[i] = vuzp2q_s16(t.val[i], t.val[i + 1]);                              \
  t.val[i + 1] = vaddq_s16(t.val[i], neon_one);                               \
  t.val[i + 1] = vshrq_n_s16(t.val[i + 1], 10);                               \
  inout = vmlsq_s16(inout, t.val[i + 1], neon_kyberq);

/*************************************************
* Name:        neon_polyvec_acc_montgomery
*
* Description: Multiply elements of a and b in NTT domain, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - poly *r: pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void neon_polyvec_acc_montgomery(poly *c, const polyvec *a, const polyvec *b, const int to_mont)
{
  int16x8x4_t aa, bb, r, ta, tb, t;                              // 24
  int16x8_t neon_v, neon_qinv, neon_kyberq, neon_zeta, neon_one; // 5

  // Declare constant
  neon_qinv = vdupq_n_s16(QINV);
  neon_kyberq = vdupq_n_s16(KYBER_Q);
  neon_v = vdupq_n_s16(_V);
  neon_one = vdupq_n_s16(1 << 9);

  // Scalar variable
  unsigned int k = 80;
  unsigned int j, i;
  // End

  // Total possible register: Max 30;
  // 1st Iteration
  for (j = 0; j < KYBER_N; j += 32)
  {
    // Load Zeta
    // 64, 65, 66, 67 =-= 68, 69, 70, 71
    neon_zeta = vld1q_s16(&neon_zetas[k]);

    // Use max 8 registers
    // 0: 0, 4,  8, 12, =-=  16, 20, 24, 28
    // 1: 1, 5,  9, 13, =-=  17, 21, 25, 29
    // 2: 2, 6, 10, 14, =-=  18, 22, 26, 30
    // 3: 3, 7, 11, 15, =-=  19, 23, 27, 31
    vload4(aa, &a->vec[0].coeffs[j]);
    vload4(bb, &b->vec[0].coeffs[j]);

    // => r.val[0] = a.val[1]*b.val[1]*zeta_pos + a.val[0] * b.val[0]
    // => r.val[1] = a.val[0]*b.val[1] + a.val[1] * b.val[0]
    // => r.val[2] = a.val[3]*b.val[3]*zetas_neg + a.val[2]*b.val[2]
    // => r.val[3] = a.val[2]*b.val[3] + a.val[3] * b.val[2]

    fqmul(ta.val[0], aa.val[1], bb.val[1], t);
    fqmul(ta.val[0], ta.val[0], neon_zeta, t);
    fqmul(ta.val[1], aa.val[0], bb.val[1], t);
    fqmul(ta.val[2], aa.val[3], bb.val[3], t);
    fqmul(ta.val[2], ta.val[2], neon_zeta, t);
    fqmul(ta.val[3], aa.val[2], bb.val[3], t);

    fqmul(tb.val[0], aa.val[0], bb.val[0], t);
    fqmul(tb.val[1], aa.val[1], bb.val[0], t);
    fqmul(tb.val[2], aa.val[2], bb.val[2], t);
    fqmul(tb.val[3], aa.val[3], bb.val[2], t);

    vadd8(r.val[0], ta.val[0], tb.val[0]);
    vadd8(r.val[1], ta.val[1], tb.val[1]);
    vsub8(r.val[2], tb.val[2], ta.val[2]);
    vadd8(r.val[3], ta.val[3], tb.val[3]);

    /***************************/

    // 2nd iterator
    vload4(aa, &a->vec[1].coeffs[j]);
    vload4(bb, &b->vec[1].coeffs[j]);

    fqmul(ta.val[0], aa.val[1], bb.val[1], t);
    fqmul(ta.val[0], ta.val[0], neon_zeta, t);
    fqmul(ta.val[1], aa.val[0], bb.val[1], t);
    fqmul(ta.val[2], aa.val[3], bb.val[3], t);
    fqmul(ta.val[2], ta.val[2], neon_zeta, t);
    fqmul(ta.val[3], aa.val[2], bb.val[3], t);

    vadd8(r.val[0], r.val[0], ta.val[0]);
    vadd8(r.val[1], r.val[1], ta.val[1]);
    vsub8(r.val[2], r.val[2], ta.val[2]);
    vadd8(r.val[3], r.val[3], ta.val[3]);

    fqmul(tb.val[0], aa.val[0], bb.val[0], t);
    fqmul(tb.val[1], aa.val[1], bb.val[0], t);
    fqmul(tb.val[2], aa.val[2], bb.val[2], t);
    fqmul(tb.val[3], aa.val[3], bb.val[2], t);

    vadd8(r.val[0], r.val[0], tb.val[0]);
    vadd8(r.val[1], r.val[1], tb.val[1]);
    vadd8(r.val[2], r.val[2], tb.val[2]);
    vadd8(r.val[3], r.val[3], tb.val[3]);

    /***************************/

#if KYBER_K >= 3
    // 3rd iterator
    vload4(aa, &a->vec[2].coeffs[j]);
    vload4(bb, &b->vec[2].coeffs[j]);

    fqmul(ta.val[0], aa.val[1], bb.val[1], t);
    fqmul(ta.val[0], ta.val[0], neon_zeta, t);
    fqmul(ta.val[1], aa.val[0], bb.val[1], t);
    fqmul(ta.val[2], aa.val[3], bb.val[3], t);
    fqmul(ta.val[2], ta.val[2], neon_zeta, t);
    fqmul(ta.val[3], aa.val[2], bb.val[3], t);

    vadd8(r.val[0], r.val[0], ta.val[0]);
    vadd8(r.val[1], r.val[1], ta.val[1]);
    vsub8(r.val[2], r.val[2], ta.val[2]);
    vadd8(r.val[3], r.val[3], ta.val[3]);

    fqmul(tb.val[0], aa.val[0], bb.val[0], t);
    fqmul(tb.val[1], aa.val[1], bb.val[0], t);
    fqmul(tb.val[2], aa.val[2], bb.val[2], t);
    fqmul(tb.val[3], aa.val[3], bb.val[2], t);

    vadd8(r.val[0], r.val[0], tb.val[0]);
    vadd8(r.val[1], r.val[1], tb.val[1]);
    vadd8(r.val[2], r.val[2], tb.val[2]);
    vadd8(r.val[3], r.val[3], tb.val[3]);
#endif
#if KYBER_K == 4
    // 3rd iterator
    vload4(aa, &a->vec[3].coeffs[j]);
    vload4(bb, &b->vec[3].coeffs[j]);

    fqmul(ta.val[0], aa.val[1], bb.val[1], t);
    fqmul(ta.val[0], ta.val[0], neon_zeta, t);
    fqmul(ta.val[1], aa.val[0], bb.val[1], t);
    fqmul(ta.val[2], aa.val[3], bb.val[3], t);
    fqmul(ta.val[2], ta.val[2], neon_zeta, t);
    fqmul(ta.val[3], aa.val[2], bb.val[3], t);

    vadd8(r.val[0], r.val[0], ta.val[0]);
    vadd8(r.val[1], r.val[1], ta.val[1]);
    vsub8(r.val[2], r.val[2], ta.val[2]);
    vadd8(r.val[3], r.val[3], ta.val[3]);

    fqmul(tb.val[0], aa.val[0], bb.val[0], t);
    fqmul(tb.val[1], aa.val[1], bb.val[0], t);
    fqmul(tb.val[2], aa.val[2], bb.val[2], t);
    fqmul(tb.val[3], aa.val[3], bb.val[2], t);

    vadd8(r.val[0], r.val[0], tb.val[0]);
    vadd8(r.val[1], r.val[1], tb.val[1]);
    vadd8(r.val[2], r.val[2], tb.val[2]);
    vadd8(r.val[3], r.val[3], tb.val[3]);
#endif

    // Do poly_reduce:   poly_reduce(r);
    barrett(r.val[0], t, 0);
    barrett(r.val[1], t, 2);
    barrett(r.val[2], t, 0);
    barrett(r.val[3], t, 2);

    if (to_mont)
    {
      neon_zeta = vdupq_n_s16(((1ULL << 32) % KYBER_Q));

      // Split fqmul
      fqmul(r.val[0], r.val[0], neon_zeta, t);
      fqmul(r.val[1], r.val[1], neon_zeta, t);
      fqmul(r.val[2], r.val[2], neon_zeta, t);
      fqmul(r.val[3], r.val[3], neon_zeta, t);
    }

    vstore4(&c->coeffs[j], r);
    i = (j != 96) ? 0 : 80;
    k += 8 + i;
  }
}
