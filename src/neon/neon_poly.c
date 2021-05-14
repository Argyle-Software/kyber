#include <arm_neon.h>
#include "params.h"
#include "poly.h"
#include "neon_ntt.h"
#include "cbd.h"
#include "symmetric.h"

/*************************************************
* Name:        neon_poly_getnoise_eta1_2x
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA1
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*                                     (of length KYBER_SYMBYTES bytes)
*              - uint8_t nonce: one-byte input nonce
**************************************************/
void neon_poly_getnoise_eta1_2x(poly *vec1, poly *vec2,
                                const uint8_t seed[KYBER_SYMBYTES],
                                uint8_t nonce1, uint8_t nonce2)
{
  uint8_t buf1[KYBER_ETA1 * KYBER_N / 4],
      buf2[KYBER_ETA1 * KYBER_N / 4];
  neon_prf(buf1, buf2, sizeof(buf1), seed, nonce1, nonce2);
  poly_cbd_eta1(vec1, buf1);
  poly_cbd_eta1(vec2, buf2);
}

/*************************************************
* Name:        neon_poly_getnoise_eta2_2x
*              neon_poly_getnoise_eta2
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA2
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*                                     (of length KYBER_SYMBYTES bytes)
*              - uint8_t nonce: one-byte input nonce
**************************************************/
void neon_poly_getnoise_eta2_2x(poly *vec1, poly *vec2,
                                const uint8_t seed[KYBER_SYMBYTES],
                                uint8_t nonce1, uint8_t nonce2)
{
  uint8_t buf1[KYBER_ETA2 * KYBER_N / 4],
      buf2[KYBER_ETA2 * KYBER_N / 4];
  neon_prf(buf1, buf2, sizeof(buf1), seed, nonce1, nonce2);
  poly_cbd_eta2(vec1, buf1);
  poly_cbd_eta2(vec2, buf2);
}

void neon_poly_getnoise_eta2(poly *r,
                             const uint8_t seed[KYBER_SYMBYTES],
                             uint8_t nonce)
{
  uint8_t buf[KYBER_ETA2 * KYBER_N / 4];
  prf(buf, sizeof(buf), seed, nonce);
  poly_cbd_eta2(r, buf);
}

/*************************************************
* Name:        neon_ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *r: pointer to in/output polynomial
**************************************************/
void neon_poly_ntt(poly *r)
{
  neon_ntt(r->coeffs);
  neon_poly_reduce(r);
}

/*************************************************
* Name:        neon_invntt
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
*              of a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void neon_poly_invntt_tomont(poly *r)
{
  neon_invntt(r->coeffs);
}

/*************************************************/
// Load int16x8x4_t c <= ptr*
#define vloadx4(c, ptr) c = vld1q_s16_x4(ptr);

// Load int16x8x4_t c <= ptr*
#define vstorex4(ptr, c) vst1q_s16_x4(ptr, c);

// c (int16x8) = a + b (int16x8)
#define vadd(c, a, b) c = vaddq_s16(a, b);

// c (int16x8) = a + b (int16x8)
#define vand(c, a, b) c = vandq_s16((int16x8_t)a, b);

// c (int16x8) = a - b (int16x8)
#define vsub(c, a, b) c = vsubq_s16(a, b);

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
* Name:        poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r: pointer to input/output polynomial
**************************************************/
void neon_poly_reduce(poly *c)
{
  int16x8x4_t cc, t;                       // 8
  int16x8_t neon_v, neon_kyberq, neon_one; // 2

  neon_kyberq = vdupq_n_s16(KYBER_Q);
  neon_v = vdupq_n_s16(((1U << 26) + KYBER_Q / 2) / KYBER_Q);
  neon_one = vdupq_n_s16(1 << 9);

  // Total register: 18 registers.
  for (int i = 0; i < KYBER_N; i += 32)
  {
    vloadx4(cc, &c->coeffs[i]);

    // c = reduce(c)
    barrett(cc.val[0], t, 0);
    barrett(cc.val[1], t, 2);
    barrett(cc.val[2], t, 0);
    barrett(cc.val[3], t, 2);

    // c = t;
    vstorex4(&c->coeffs[i], cc);
  }
}

/*************************************************
* Name:        neon_poly_add_reduce
*
* Description: Add two polynomials; no modular reduction is performed
*              Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments: - poly *r: pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void neon_poly_add_reduce(poly *c, const poly *a)
{
  int16x8x4_t cc, aa, t;                   // 12
  int16x8_t neon_v, neon_kyberq, neon_one; // 2

  neon_kyberq = vdupq_n_s16(KYBER_Q);
  neon_v = vdupq_n_s16(((1U << 26) + KYBER_Q / 2) / KYBER_Q);
  neon_one = vdupq_n_s16(1 << 9);

  // Total register: 14 registers.
  unsigned int i;
  for (i = 0; i < KYBER_N; i += 32)
  {
    vloadx4(aa, &a->coeffs[i]);
    vloadx4(cc, &c->coeffs[i]);

    // c = c - a;
    vadd(cc.val[0], cc.val[0], aa.val[0]);
    vadd(cc.val[1], cc.val[1], aa.val[1]);
    vadd(cc.val[2], cc.val[2], aa.val[2]);
    vadd(cc.val[3], cc.val[3], aa.val[3]);

    // c = reduce(c)
    barrett(cc.val[0], t, 0);
    barrett(cc.val[1], t, 2);
    barrett(cc.val[2], t, 0);
    barrett(cc.val[3], t, 2);

    // c = t;
    vstorex4(&c->coeffs[i], cc);
  }
}

void neon_poly_add_add_reduce(poly *c, const poly *a, const poly *b)
{
  int16x8x4_t cc, aa, bb, t;               // 16
  int16x8_t neon_v, neon_kyberq, neon_one; // 2

  neon_kyberq = vdupq_n_s16(KYBER_Q);
  neon_v = vdupq_n_s16(((1U << 26) + KYBER_Q / 2) / KYBER_Q);
  neon_one = vdupq_n_s16(1 << 9);

  // Total register: 18 registers.
  unsigned int i;
  for (i = 0; i < KYBER_N; i += 32)
  {
    vloadx4(aa, &a->coeffs[i]);
    vloadx4(bb, &b->coeffs[i]);
    vloadx4(cc, &c->coeffs[i]);

    // a' = a + b;
    vadd(aa.val[0], aa.val[0], bb.val[0]);
    vadd(aa.val[1], aa.val[1], bb.val[1]);
    vadd(aa.val[2], aa.val[2], bb.val[2]);
    vadd(aa.val[3], aa.val[3], bb.val[3]);

    // c = c + a' = c + a + b;
    vadd(cc.val[0], cc.val[0], aa.val[0]);
    vadd(cc.val[1], cc.val[1], aa.val[1]);
    vadd(cc.val[2], cc.val[2], aa.val[2]);
    vadd(cc.val[3], cc.val[3], aa.val[3]);

    // c = reduce(c)
    barrett(cc.val[0], t, 0);
    barrett(cc.val[1], t, 2);
    barrett(cc.val[2], t, 0);
    barrett(cc.val[3], t, 2);

    // c = t;
    vstorex4(&c->coeffs[i], cc);
  }
}

/*************************************************
* Name:        neon_poly_sub_reduce
*
* Description: Subtract two polynomials; no modular reduction is performed
*              Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void neon_poly_sub_reduce(poly *c, const poly *a)
{
  int16x8x4_t cc, aa, t;                   // 12
  int16x8_t neon_v, neon_kyberq, neon_one; // 2

  neon_kyberq = vdupq_n_s16(KYBER_Q);
  neon_v = vdupq_n_s16(((1U << 26) + KYBER_Q / 2) / KYBER_Q);
  neon_one = vdupq_n_s16(1 << 9);

  // Total register: 14 registers.
  unsigned int i;
  for (i = 0; i < KYBER_N; i += 32)
  {
    vloadx4(aa, &a->coeffs[i]);
    vloadx4(cc, &c->coeffs[i]);

    // c = c - a;
    vsub(cc.val[0], cc.val[0], aa.val[0]);
    vsub(cc.val[1], cc.val[1], aa.val[1]);
    vsub(cc.val[2], cc.val[2], aa.val[2]);
    vsub(cc.val[3], cc.val[3], aa.val[3]);

    // c = reduce(c)
    barrett(cc.val[0], t, 0);
    barrett(cc.val[1], t, 2);
    barrett(cc.val[2], t, 0);
    barrett(cc.val[3], t, 2);

    // c = t;
    vstorex4(&c->coeffs[i], cc);
  }
}
