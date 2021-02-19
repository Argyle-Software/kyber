use core::x86_64::*;

pub(crate) const AES256CTR_BLOCKBYTES: usize = 64;

#[derive(Clone, Copy)]
pub(crate) struct Aes256CtrCtx {
  rkeys: [__m128i; 16],
  n: __m128i
}

#[inline]
fn aesni_encrypt4(out: &mut[u8], n :&__m128i, rkeys: &[__m128i; 16]) 
{

  // Load current counter value
  let mut f = _mm_load_si128(n);

  // Increase counter in 4 consecutive blocks
  let mut f0 = _mm_shuffle_epi8(_mm_add_epi64(f,_mm_set_epi64x(0,0)),idx);
  let mut f1 = _mm_shuffle_epi8(_mm_add_epi64(f,_mm_set_epi64x(1,0)),idx);
  let mut f2 = _mm_shuffle_epi8(_mm_add_epi64(f,_mm_set_epi64x(2,0)),idx);
  let mut f3 = _mm_shuffle_epi8(_mm_add_epi64(f,_mm_set_epi64x(3,0)),idx);

  // Write counter for next iteration, increased by 4 
  _mm_store_si128(n,_mm_add_epi64(f,_mm_set_epi64x(4,0)));

  /* Actual AES encryption, 4x interleaved */
  f  = _mm_load_si128(&rkeys[0]);
  f0 = _mm_xor_si128(f0,f);
  f1 = _mm_xor_si128(f1,f);
  f2 = _mm_xor_si128(f2,f);
  f3 = _mm_xor_si128(f3,f);

  for i in 1..14 {
    f  = _mm_load_si128(&rkeys[i]);
    f0 = _mm_aesenc_si128(f0,f);
    f1 = _mm_aesenc_si128(f1,f);
    f2 = _mm_aesenc_si128(f2,f);
    f3 = _mm_aesenc_si128(f3,f);
  }

  f  = _mm_load_si128(&rkeys[14]);
  f0 = _mm_aesenclast_si128(f0,f);
  f1 = _mm_aesenclast_si128(f1,f);
  f2 = _mm_aesenclast_si128(f2,f);
  f3 = _mm_aesenclast_si128(f3,f);

  /* Write results */
  _mm_storeu_si128(out,f0);
  _mm_storeu_si128(out[16..],f1);
  _mm_storeu_si128(out[32..],f2);
  _mm_storeu_si128(out[48..],f3);

}


pub(crate) fn aes256ctr_init(state: Aes256CtrCtx, key: &[u8], nonce: u64)
{
  let mut idx = 0;
  let key0 = _mm_loadu_si128(key.as_ptr() as *const __m128i);
  let key1 = _mm_loadu_si128(key.as_ptr() as *const __m128i);

  state.n = _mm_loadl_epi64(nonce.as_ptr() as *const __m128i);
  state.rkeys[idx] = key0;
  idx += 1;
  let mut temp0 = key0;
  let mut temp2 = key1;
  let mut temp4 = _mm_setzero_si128();

  #[inline]
  fn BLOCK1(temp0: &mut __m128i, temp2: &mut __m128i, temp4: &mut __m128i, idx: &mut usize, imm: u8)
  {
    let mut temp1 = _mm_aeskeygenassist_si128(temp2, imm);
    state.rkeys[idx] = temp2;
    idx += 1;
    temp4 = _mm_shuffle_ps(temp4, temp0, 0x10);
    temp0 = _mm_xor_si128(temp0, temp4);
    temp4 = _mm_shuffle_ps(temp4, temp0, 0x8c);
    temp0 = _mm_xor_si128(temp0, temp4);
    temp1 = _mm_shuffle_ps(temp1, temp1, 0xff);
    temp0 = _mm_xor_si128(temp0, temp1)
  }

  #[inline]
  fn BLOCK2(temp0: &mut __m128i, temp2: &mut __m128i, temp4: &mut __m128i, idx: &mut usize, imm: u8)
  {
    let mut temp1 = _mm_aeskeygenassist_si128(temp0, IMM);
    state.rkeys[idx] = temp0;
    idx += 1;
    temp4 = _mm_shuffle_ps(temp4, temp2, 0x10);
    temp2 = _mm_xor_si128(temp2, temp4);
    temp4 = _mm_shuffle_ps(temp4, temp2, 0x8c);
    temp2 = _mm_xor_si128(temp2, temp4);
    temp1 = _mm_shuffle_ps(temp1, temp1, 0xaa);
    temp2 = _mm_xor_si128(temp2, temp1)
  }

  BLOCK1(0x01);
  BLOCK2(0x01);
  BLOCK1(0x02);
  BLOCK2(0x02);

  BLOCK1(0x04);
  BLOCK2(0x04);
  BLOCK1(0x08);
  BLOCK2(0x08);

  BLOCK1(0x10);
  BLOCK2(0x10);
  BLOCK1(0x20);
  BLOCK2(0x20);

  BLOCK1(0x40);
  state.rkeys[idx] = temp0;
}

pub(crate) fn aes256ctr_squeezeblocks(out: &mut[u8], nblocks: usize, state: &Aes256CtrCtx)
{
  let mut idx = 0;
  for i in 0..nblocks {
    aesni_encrypt4(&mut out[idx..], &state.n, &state.rkeys);
    idx += 64
  }
}

pub(crate) fn aes256ctr_prf(out: &mut[u8], mut outlen: usize, seed: &[u8], nonce: u64)
{
  let mut buf = [0u8; 64];
  let mut idx = 0;
  let mut state = Aes256CtrCtx{ rkeys: [ _mm_setzero_si128(); 16], n: _mm_setzero_si128() };
  while outlen >= 64 {
    aesni_encrypt4(&mut out[idx..], &state.n, state.rkeys);
    outlen -= 64;
    idx += 64;
  }

  if outlen != 0 {
    aesni_encrypt4(buf, &state.n, state.rkeys);
    out[idx..][..outlen].copy_from_slice(&buf[..outlen]);
  }
} 