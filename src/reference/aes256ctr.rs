// Translated from the public-domain code by Thomas Pornin as
// found in the Kyber C reference library.
// https://github.com/pq-crystals/kyber/blob/master/ref/aes256ctr.c

/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#![cfg(feature = "90s")]

pub struct Aes256CtrCtx
{
  pub sk_exp: [u64; 120],
  pub ivw: [u32; 16],
}

impl Aes256CtrCtx
{
  pub fn new() -> Self
  {
    Self {
      sk_exp: [0u64; 120],
      ivw: [0u32; 16],
    }
  }
}

fn br_dec32le(src: &[u8]) -> u32
{
  src[0] as u32
    | (src[1] as u32) << 8
    | (src[2] as u32) << 16
    | (src[3] as u32) << 24
}

fn br_range_dec32le(v: &mut [u32], mut num: usize, src: &[u8])
{
  let mut v_idx: usize = 0;
  let mut src_idx: usize = 0;
  while num > 0 {
    num -= 1;
    v[v_idx] = br_dec32le(&src[src_idx..]);
    v_idx += 1;
    src_idx += 4;
  }
}

fn br_swap32(mut x: u32) -> u32
{
  x = ((x & 0x00FF00FFu32) << 8) | ((x >> 8) & 0x00FF00FFu32);
  (x << 16) | (x >> 16)
}

fn br_enc32le(dst: &mut [u8], x: u32)
{
  dst[0] = x as u8;
  dst[1] = (x >> 8) as u8;
  dst[2] = (x >> 16) as u8;
  dst[3] = (x >> 24) as u8;
}

fn br_range_enc32le(dst: &mut [u8], v: &[u32], mut num: usize)
{
  let mut v_idx = 0;
  let mut dst_idx = 0;
  while num > 0 {
    br_enc32le(&mut dst[dst_idx..], v[v_idx]);
    v_idx += 1;
    dst_idx += 4;
    num -= 1;
  }
}

#[rustfmt::skip]
fn br_aes_ct64_bitslice_sbox(q: &mut [u64])
{
  // This S-box implementation is a straightforward translation of
  // the circuit described by Boyar and Peralta in "A new
  // combinational logic minimization technique with applications
  // to cryptology" (https://eprint.iacr.org/2009/191.pdf).
  // Note that variables x(input) and s(output) are numbered
  // in "reverse" order (x0 is the high bit, x7 is the low bit).

  let x0 = q[7];
  let x1 = q[6];
  let x2 = q[5];
  let x3 = q[4];
  let x4 = q[3];
  let x5 = q[2];
  let x6 = q[1];
  let x7 = q[0];

  // Top linear transformation.
  let y14 = x3 ^ x5;
  let y13 = x0 ^ x6;
  let y9 = x0 ^ x3;
  let y8 = x0 ^ x5;
  let t0 = x1 ^ x2;
  let y1 = t0 ^ x7;
  let y4 = y1 ^ x3;
  let y12 = y13 ^ y14;
  let y2 = y1 ^ x0;
  let y5 = y1 ^ x6;
  let y3 = y5 ^ y8;
  let t1 = x4 ^ y12;
  let y15 = t1 ^ x5;
  let y20 = t1 ^ x1;
  let y6 = y15 ^ x7;
  let y10 = y15 ^ t0;
  let y11 = y20 ^ y9;
  let y7 = x7 ^ y11;
  let y17 = y10 ^ y11;
  let y19 = y10 ^ y8;
  let y16 = t0 ^ y11;
  let y21 = y13 ^ y16;
  let y18 = x0 ^ y16;

  // Non-linear section.
  let t2 = y12 & y15;
  let t3 = y3 & y6;
  let t4 = t3 ^ t2;
  let t5 = y4 & x7;
  let t6 = t5 ^ t2;
  let t7 = y13 & y16;
  let t8 = y5 & y1;
  let t9 = t8 ^ t7;
  let t10 = y2 & y7;
  let t11 = t10 ^ t7;
  let t12 = y9 & y11;
  let t13 = y14 & y17;
  let t14 = t13 ^ t12;
  let t15 = y8 & y10;
  let t16 = t15 ^ t12;
  let t17 = t4 ^ t14;
  let t18 = t6 ^ t16;
  let t19 = t9 ^ t14;
  let t20 = t11 ^ t16;
  let t21 = t17 ^ y20;
  let t22 = t18 ^ y19;
  let t23 = t19 ^ y21;
  let t24 = t20 ^ y18;

  let t25 = t21 ^ t22;
  let t26 = t21 & t23;
  let t27 = t24 ^ t26;
  let t28 = t25 & t27;
  let t29 = t28 ^ t22;
  let t30 = t23 ^ t24;
  let t31 = t22 ^ t26;
  let t32 = t31 & t30;
  let t33 = t32 ^ t24;
  let t34 = t23 ^ t33;
  let t35 = t27 ^ t33;
  let t36 = t24 & t35;
  let t37 = t36 ^ t34;
  let t38 = t27 ^ t36;
  let t39 = t29 & t38;
  let t40 = t25 ^ t39;

  let t41 = t40 ^ t37;
  let t42 = t29 ^ t33;
  let t43 = t29 ^ t40;
  let t44 = t33 ^ t37;
  let t45 = t42 ^ t41;
  let z0 = t44 & y15;
  let z1 = t37 & y6;
  let z2 = t33 & x7;
  let z3 = t43 & y16;
  let z4 = t40 & y1;
  let z5 = t29 & y7;
  let z6 = t42 & y11;
  let z7 = t45 & y17;
  let z8 = t41 & y10;
  let z9 = t44 & y12;
  let z10 = t37 & y3;
  let z11 = t33 & y4;
  let z12 = t43 & y13;
  let z13 = t40 & y5;
  let z14 = t29 & y2;
  let z15 = t42 & y9;
  let z16 = t45 & y14;
  let z17 = t41 & y8;

  // Bottom linear transformation.
  let t46 = z15 ^ z16;
  let t47 = z10 ^ z11;
  let t48 = z5 ^ z13;
  let t49 = z9 ^ z10;
  let t50 = z2 ^ z12;
  let t51 = z2 ^ z5;
  let t52 = z7 ^ z8;
  let t53 = z0 ^ z3;
  let t54 = z6 ^ z7;
  let t55 = z16 ^ z17;
  let t56 = z12 ^ t48;
  let t57 = t50 ^ t53;
  let t58 = z4 ^ t46;
  let t59 = z3 ^ t54;
  let t60 = t46 ^ t57;
  let t61 = z14 ^ t57;
  let t62 = t52 ^ t58;
  let t63 = t49 ^ t58;
  let t64 = z4 ^ t59;
  let t65 = t61 ^ t62;
  let t66 = z1 ^ t63;
  let s0 = t59 ^ t63;
  let s6 = t56 ^ !t62;
  let s7 = t48 ^ !t60;
  let t67 = t64 ^ t65;
  let s3 = t53 ^ t66;
  let s4 = t51 ^ t66;
  let s5 = t47 ^ t65;
  let s1 = t64 ^ !s3;
  let s2 = t55 ^ !t67;

  q[7] = s0;
  q[6] = s1;
  q[5] = s2;
  q[4] = s3;
  q[3] = s4;
  q[2] = s5;
  q[1] = s6;
  q[0] = s7;
}

fn swapn(cl: u64, ch: u64, s: usize, x: u64, y: &mut u64) -> u64
{
  let a = x;
  let b = *y;
  *y = ((a & ch) >> (s)) | (b & ch); // update y
  (a & cl) | ((b & cl) << s) // return x
}

fn swap2(x: u64, y: &mut u64) -> u64
{
  swapn(0x5555555555555555u64, 0xAAAAAAAAAAAAAAAAu64, 1, x, y)
}

fn swap4(x: u64, y: &mut u64) -> u64
{
  swapn(0x3333333333333333u64, 0xCCCCCCCCCCCCCCCCu64, 2, x, y)
}

fn swap8(x: u64, y: &mut u64) -> u64
{
  swapn(0x0F0F0F0F0F0F0F0Fu64, 0xF0F0F0F0F0F0F0F0u64, 4, x, y)
}

fn br_aes_ct64_ortho(q: &mut [u64])
{
  q[0] = swap2(q[0], &mut q[1]);
  q[2] = swap2(q[2], &mut q[3]);
  q[4] = swap2(q[4], &mut q[5]);
  q[6] = swap2(q[6], &mut q[7]);

  q[0] = swap4(q[0], &mut q[2]);
  q[1] = swap4(q[1], &mut q[3]);
  q[4] = swap4(q[4], &mut q[6]);
  q[5] = swap4(q[5], &mut q[7]);

  q[0] = swap8(q[0], &mut q[4]);
  q[1] = swap8(q[1], &mut q[5]);
  q[2] = swap8(q[2], &mut q[6]);
  q[3] = swap8(q[3], &mut q[7]);
}

fn br_aes_ct64_interleave_in(q0: &mut u64, q1: &mut u64, w: &[u32])
{
  let (mut x0, mut x1, mut x2, mut x3): (u64, u64, u64, u64);

  x0 = w[0].into();
  x1 = w[1].into();
  x2 = w[2].into();
  x3 = w[3].into();
  x0 |= x0 << 16;
  x1 |= x1 << 16;
  x2 |= x2 << 16;
  x3 |= x3 << 16;
  x0 &= 0x0000FFFF0000FFFFu64;
  x1 &= 0x0000FFFF0000FFFFu64;
  x2 &= 0x0000FFFF0000FFFFu64;
  x3 &= 0x0000FFFF0000FFFFu64;
  x0 |= x0 << 8;
  x1 |= x1 << 8;
  x2 |= x2 << 8;
  x3 |= x3 << 8;
  x0 &= 0x00FF00FF00FF00FFu64;
  x1 &= 0x00FF00FF00FF00FFu64;
  x2 &= 0x00FF00FF00FF00FFu64;
  x3 &= 0x00FF00FF00FF00FFu64;
  *q0 = x0 | (x2 << 8);
  *q1 = x1 | (x3 << 8);
}

fn br_aes_ct64_interleave_out(w: &mut [u32], q0: u64, q1: u64)
{
  let (mut x0, mut x1, mut x2, mut x3): (u64, u64, u64, u64);

  x0 = q0 & 0x00FF00FF00FF00FFu64;
  x1 = q1 & 0x00FF00FF00FF00FFu64;
  x2 = (q0 >> 8) & 0x00FF00FF00FF00FFu64;
  x3 = (q1 >> 8) & 0x00FF00FF00FF00FFu64;
  x0 |= x0 >> 8;
  x1 |= x1 >> 8;
  x2 |= x2 >> 8;
  x3 |= x3 >> 8;
  x0 &= 0x0000FFFF0000FFFFu64;
  x1 &= 0x0000FFFF0000FFFFu64;
  x2 &= 0x0000FFFF0000FFFFu64;
  x3 &= 0x0000FFFF0000FFFFu64;
  w[0] = x0 as u32 | (x0 >> 16) as u32;
  w[1] = x1 as u32 | (x1 >> 16) as u32;
  w[2] = x2 as u32 | (x2 >> 16) as u32;
  w[3] = x3 as u32 | (x3 >> 16) as u32;
}

fn sub_word(x: u32) -> u32
{
  let mut q = [0u64; 8];
  q[0] = x.into();
  br_aes_ct64_ortho(&mut q);
  br_aes_ct64_bitslice_sbox(&mut q);
  br_aes_ct64_ortho(&mut q);
  q[0] as u32
}

const RCON: [u32; 10] =
  [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

fn br_aes_ct64_keysched(comp_skey: &mut [u64], key: &[u8])
{
  let (mut j, mut k) = (0usize, 0usize);
  let mut skey = [0u32; 60];

  let key_len = 32usize;

  let nk = key_len >> 2;
  let nkf = (14 + 1) << 2;
  br_range_dec32le(&mut skey, (key_len >> 2) as usize, key);
  let mut tmp = skey[(key_len >> 2) - 1];
  for i in nk..nkf {
    if j == 0 {
      tmp = (tmp << 24) | (tmp >> 8);
      tmp = sub_word(tmp) ^ RCON[k];
    } else if nk > 6 && j == 4 {
      tmp = sub_word(tmp);
    }
    tmp ^= skey[i - nk];
    skey[i] = tmp;
    j += 1;
    if j == nk {
      j = 0;
      k += 1;
    }
  }

  j = 0;
  for idx in (0..nkf).step_by(4) {
    let mut q = [0u64; 8];

    let (q0, q1) = q.split_at_mut(4);
    br_aes_ct64_interleave_in(&mut q0[0], &mut q1[0], &skey[idx..]);
    q[1] = q[0];
    q[2] = q[0];
    q[3] = q[0];
    q[5] = q[4];
    q[6] = q[4];
    q[7] = q[4];
    br_aes_ct64_ortho(&mut q);
    comp_skey[j] = (q[0] & 0x1111111111111111)
      | (q[1] & 0x2222222222222222)
      | (q[2] & 0x4444444444444444)
      | (q[3] & 0x8888888888888888);
    comp_skey[j + 1] = (q[4] & 0x1111111111111111)
      | (q[5] & 0x2222222222222222)
      | (q[6] & 0x4444444444444444)
      | (q[7] & 0x8888888888888888);
    j += 2;
  }
}

fn br_aes_ct64_skey_expand(skey: &mut [u64], comp_skey: &[u64])
{
  const N: usize = 15 << 1;
  let mut u = 0;
  let mut v = 0;
  let mut x0: u64;
  let mut x1: u64;
  let mut x2: u64;
  let mut x3: u64;
  while u < N {
    x0 = comp_skey[u];
    x1 = comp_skey[u];
    x2 = comp_skey[u];
    x3 = comp_skey[u];
    x0 &= 0x1111111111111111;
    x1 &= 0x2222222222222222;
    x2 &= 0x4444444444444444;
    x3 &= 0x8888888888888888;
    x1 >>= 1;
    x2 >>= 2;
    x3 >>= 3;
    skey[v] = (x0 << 4).wrapping_sub(x0);
    skey[v + 1] = (x1 << 4).wrapping_sub(x1);
    skey[v + 2] = (x2 << 4).wrapping_sub(x2);
    skey[v + 3] = (x3 << 4).wrapping_sub(x3);
    v += 4;
    u += 1;
  }
}

fn add_round_key(q: &mut [u64], sk: &[u64])
{
  q[0] ^= sk[0];
  q[1] ^= sk[1];
  q[2] ^= sk[2];
  q[3] ^= sk[3];
  q[4] ^= sk[4];
  q[5] ^= sk[5];
  q[6] ^= sk[6];
  q[7] ^= sk[7];
}

fn shift_rows(q: &mut [u64])
{
  for x in q.iter_mut() {
    *x = (*x & 0x000000000000FFFF)
      | ((*x & 0x00000000FFF00000) >> 4)
      | ((*x & 0x00000000000F0000) << 12)
      | ((*x & 0x0000FF0000000000) >> 8)
      | ((*x & 0x000000FF00000000) << 8)
      | ((*x & 0xF000000000000000) >> 12)
      | ((*x & 0x0FFF000000000000) << 4)
  }
}

fn rotr32(x: u64) -> u64
{
  (x << 32) | (x >> 32)
}

fn mix_columns(q: &mut [u64])
{
  let q0 = q[0];
  let q1 = q[1];
  let q2 = q[2];
  let q3 = q[3];
  let q4 = q[4];
  let q5 = q[5];
  let q6 = q[6];
  let q7 = q[7];
  let r0 = (q0 >> 16) | (q0 << 48);
  let r1 = (q1 >> 16) | (q1 << 48);
  let r2 = (q2 >> 16) | (q2 << 48);
  let r3 = (q3 >> 16) | (q3 << 48);
  let r4 = (q4 >> 16) | (q4 << 48);
  let r5 = (q5 >> 16) | (q5 << 48);
  let r6 = (q6 >> 16) | (q6 << 48);
  let r7 = (q7 >> 16) | (q7 << 48);

  q[0] = q7 ^ r7 ^ r0 ^ rotr32(q0 ^ r0);
  q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr32(q1 ^ r1);
  q[2] = q1 ^ r1 ^ r2 ^ rotr32(q2 ^ r2);
  q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr32(q3 ^ r3);
  q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr32(q4 ^ r4);
  q[5] = q4 ^ r4 ^ r5 ^ rotr32(q5 ^ r5);
  q[6] = q5 ^ r5 ^ r6 ^ rotr32(q6 ^ r6);
  q[7] = q6 ^ r6 ^ r7 ^ rotr32(q7 ^ r7);
}

fn inc4_be(x: u32) -> u32
{
  let t = br_swap32(x) + 4;
  br_swap32(t)
}

fn aes_ctr4x(out: &mut [u8], ivw: &mut [u32], sk_exp: &[u64])
{
  let mut w = [0u32; 16];
  w.copy_from_slice(&ivw);
  let mut q = [0u64; 8];
  let (q0, q1) = q.split_at_mut(4);
  for i in 0..4 {
    br_aes_ct64_interleave_in(&mut q0[i], &mut q1[i], &w[(i << 2)..]);
  }
  br_aes_ct64_ortho(&mut q);

  add_round_key(&mut q, sk_exp);
  for i in 1..14 {
    br_aes_ct64_bitslice_sbox(&mut q);
    shift_rows(&mut q);
    mix_columns(&mut q);
    add_round_key(&mut q, &sk_exp[(i << 3)..]);
  }
  br_aes_ct64_bitslice_sbox(&mut q);
  shift_rows(&mut q);
  add_round_key(&mut q, &sk_exp[112..]);

  br_aes_ct64_ortho(&mut q);
  for i in 0..4 {
    br_aes_ct64_interleave_out(&mut w[(i << 2)..], q[i], q[i + 4]);
  }
  br_range_enc32le(out, &w, 16);

  /* Increase counter for next 4 blocks */
  ivw[3] = inc4_be(ivw[3]);
  ivw[7] = inc4_be(ivw[7]);
  ivw[11] = inc4_be(ivw[11]);
  ivw[15] = inc4_be(ivw[15]);
}

fn br_aes_ct64_ctr_init(sk_exp: &mut [u64], key: &[u8])
{
  let mut skey = [0u64; 30];
  br_aes_ct64_keysched(&mut skey, key);
  br_aes_ct64_skey_expand(sk_exp, &skey);
}

#[cfg(not(feature = "90s-fixslice"))]
fn br_aes_ct64_ctr_run(
  sk_exp: &mut [u64],
  iv: &[u8],
  cc: u32,
  data: &mut [u8],
  mut len: usize,
)
{
  let mut ivw = [0u32; 16];
  br_range_dec32le(&mut ivw, 3, iv);
  let mut slice = [0u32; 3];
  slice.copy_from_slice(&ivw[0..3]);
  ivw[4..7].copy_from_slice(&slice);
  ivw[8..11].copy_from_slice(&slice);
  ivw[12..15].copy_from_slice(&slice);
  ivw[3] = br_swap32(cc);
  ivw[7] = br_swap32(cc + 1);
  ivw[11] = br_swap32(cc + 2);
  ivw[15] = br_swap32(cc + 3);

  let mut idx = 0;
  while len > 64 {
    aes_ctr4x(&mut data[idx..], &mut ivw, sk_exp);
    idx += 64;
    len -= 64;
  }
  if len > 0 {
    let mut tmp = [0u8; 64];
    aes_ctr4x(&mut tmp, &mut ivw, sk_exp);
    data[idx..].copy_from_slice(&tmp[..len])
  }
}

// Name:        aes256_prf
//
// Description: AES256 stream generation in CTR mode using 32-bit counter,
//              nonce is zero-padded to 12 bytes, counter starts at zero
//
// Arguments:   - [u8] output:      output
//              - usize outlen:  length of requested output in bytes
//              - const [u8] key:   32-byte key
//              - const u8  nonce:  1-byte nonce (will be zero-padded to 12 bytes)
#[cfg(not(feature = "90s-fixslice"))]
pub fn aes256ctr_prf(output: &mut [u8], outlen: usize, key: &[u8], nonce: u8)
{
  let mut sk_exp = [0u64; 120];
  let mut pad_nonce = [0u8; 12];
  pad_nonce[0] = nonce;
  br_aes_ct64_ctr_init(&mut sk_exp, key);
  br_aes_ct64_ctr_run(&mut sk_exp, &pad_nonce, 0, output, outlen);
}

// Name:        aes256ctr_init
//
// Description: AES256 CTR used as a replacement for a XOF; this function
//              "absorbs" a 32-byte key and two additional bytes that are zero-padded
//              to a 12-byte nonce
//
// Arguments:   - aes256xof_ctx *s:          state to "absorb" key and IV into
//              - const [u8] key:  32-byte key
//              - [u8]  nonce:           additional bytes to "absorb"
pub fn aes256ctr_init(s: &mut Aes256CtrCtx, key: &[u8], nonce: [u8; 12])
{
  br_aes_ct64_ctr_init(&mut s.sk_exp, key);

  br_range_dec32le(&mut s.ivw, 3, &nonce);
  let mut slice = [0u32; 3];
  slice.copy_from_slice(&s.ivw[..3]);
  s.ivw[4..7].copy_from_slice(&slice);
  s.ivw[8..11].copy_from_slice(&slice);
  s.ivw[12..15].copy_from_slice(&slice);
  s.ivw[3] = br_swap32(0);
  s.ivw[7] = br_swap32(1);
  s.ivw[11] = br_swap32(2);
  s.ivw[15] = br_swap32(3);
}

pub fn aes256ctr_squeezeblocks(
  out: &mut [u8],
  mut nblocks: usize,
  s: &mut Aes256CtrCtx,
)
{
  let mut idx = 0;
  while nblocks > 0 {
    aes_ctr4x(&mut out[idx..], &mut s.ivw, &s.sk_exp);
    idx += 64;
    nblocks -= 1;
  }
}
