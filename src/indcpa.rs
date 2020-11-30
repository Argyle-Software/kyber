// #![allow(clippy::needless_range_loop)]
use crate::{
  poly::*,
  polyvec::*,
  rng::*,
  symmetric::*,
  params::*,
  RngCore,
  CryptoRng,
  KyberError
};

// Name:        pack_pk
//
// Description: Serialize the public key as concatenation of the
//              serialized vector of polynomials pk
//              and the public seed used to generate the matrix A.
//
// Arguments:   unsigned char *r:          pointer to the output serialized public key
//              const poly *pk:            pointer to the input public-key polynomial
//              const unsigned char *seed: pointer to the input public seed
fn pack_pk(r: &mut[u8], pk: &mut Polyvec, seed: &[u8])
{
  polyvec_tobytes(r, pk);
  r[KYBER_POLYVECBYTES..(KYBER_SYMBYTES + KYBER_POLYVECBYTES)]
    .copy_from_slice(&seed[..KYBER_SYMBYTES]);
}

// Name:        unpack_pk
//
// Description: De-serialize public key from a byte array;
//              approximate inverse of pack_pk
//
// Arguments:   - polyvec *pk:                   pointer to output public-key vector of polynomials
//              - unsigned char *seed:           pointer to output seed to generate matrix A
//              - const unsigned char *packedpk: pointer to input serialized public key
fn unpack_pk(pk: &mut Polyvec, seed: &mut[u8], packedpk: &[u8])
{
  
  polyvec_frombytes(pk, packedpk);
  seed[..KYBER_SYMBYTES]
    .copy_from_slice(&packedpk[KYBER_POLYVECBYTES..(KYBER_SYMBYTES + KYBER_POLYVECBYTES)]);
}

// Name:        pack_sk
//
// Description: Serialize the secret key
//
// Arguments:   - unsigned char *r:  pointer to output serialized secret key
//              - const polyvec *sk: pointer to input vector of polynomials (secret key)
fn pack_sk(r: &mut[u8], sk: &mut Polyvec)
{
  polyvec_tobytes(r, sk);
}

// Name:        unpack_sk
//
// Description: De-serialize the secret key;
//              inverse of pack_sk
//
// Arguments:   - polyvec *sk:                   pointer to output vector of polynomials (secret key)
//              - const unsigned char *packedsk: pointer to input serialized secret key
fn unpack_sk(sk: &mut Polyvec, packedsk: &[u8])
{
  polyvec_frombytes(sk, packedsk);
}

// Name:        pack_ciphertext
//
// Description: Serialize the ciphertext as concatenation of the
//              compressed and serialized vector of polynomials b
//              and the compressed and serialized polynomial v
//
// Arguments:   unsigned char *r:          pointer to the output serialized ciphertext
//              const poly *pk:            pointer to the input vector of polynomials b
//              const unsigned char *seed: pointer to the input polynomial v
fn pack_ciphertext(r: &mut[u8], b: &mut Polyvec, v: &mut Poly)
{
  polyvec_compress(r, b);
  poly_compress(&mut r[KYBER_POLYVECCOMPRESSEDBYTES..], v);
}

// Name:        unpack_ciphertext
//
// Description: De-serialize and decompress ciphertext from a byte array;
//              approximate inverse of pack_ciphertext
//
// Arguments:   - polyvec *b:             pointer to the output vector of polynomials b
//              - poly *v:                pointer to the output polynomial v
//              - const unsigned char *c: pointer to the input serialized ciphertext
fn unpack_ciphertext(b: &mut Polyvec, v: &mut Poly, c: &[u8])
{
  polyvec_decompress(b, c);
  poly_decompress(v, &c[KYBER_POLYVECCOMPRESSEDBYTES..]);
}

// Name:        rej_uniform
//
// Description: Run rejection sampling on uniform random bytes to generate
//              uniform random integers mod q
//
// Arguments:   - int16_t *r:               pointer to output buffer
//              - unsigned int len:         requested number of 16-bit integers (uniform mod q)
//              - const unsigned char *buf: pointer to input buffer (assumed to be uniform random bytes)
//              - unsigned int buflen:      length of input buffer in bytes
//
// Returns number of sampled 16-bit integers (at most len)
fn rej_uniform(r: &mut[i16], len: usize, buf: &[u8], buflen: usize) -> usize
{
  let (mut ctr, mut pos) = (0usize, 0usize);
  let mut val;

  while ctr < len && pos + 2 <= buflen {
    
    val = buf[pos] as u16 | (buf[pos+1] as u16) << 8 ;
    pos += 2;

    if val < 19*KYBER_Q as u16
    {
      val -= (val >> 12) * KYBER_Q as u16; // Barrett reduction
      r[ctr] = val as i16;
      ctr += 1;
    }
  }
  ctr
}

fn gen_a(a: &mut [Polyvec], b: &[u8]) 
{
  gen_matrix(a, b, false);
}


fn gen_at(a: &mut [Polyvec], b: &[u8]) 
{
  gen_matrix(a, b, true);
}


// Name:        gen_matrix
//
// Description: Deterministically generate matrix A (or the transpose of A)
//              from a seed. Entries of the matrix are polynomials that look
//              uniformly random. Performs rejection sampling on output of
//              a XOF
//
// Arguments:   - polyvec *a:                pointer to ouptput matrix A
//              - const unsigned char *seed: pointer to input seed
//              - int transposed:            boolean deciding whether A or A^T is generated
fn gen_matrix(a: &mut [Polyvec], seed: &[u8], transposed: bool)
{ 
  let mut ctr;
  // 530 is expected number of required bytes
  const MAXNBLOCKS: usize = (530+XOF_BLOCKBYTES)/XOF_BLOCKBYTES;
  let mut buf = [0u8; XOF_BLOCKBYTES*MAXNBLOCKS+1];

  let mut state = XofState::new();

  for i in 0..KYBER_K {
    for j in 0..KYBER_K {
      if transposed {
        xof_absorb(&mut state, seed, i as u8, j as u8);
      }
      else {
        xof_absorb(&mut state, seed, j as u8, i as u8);
      }
      xof_squeezeblocks(&mut buf, MAXNBLOCKS as u64, &mut state);
      ctr = rej_uniform(&mut a[i].vec[j].coeffs, KYBER_N, &buf, MAXNBLOCKS*XOF_BLOCKBYTES);

      while ctr < KYBER_N
      {
        xof_squeezeblocks(&mut buf, 1, &mut state);
        ctr += rej_uniform(&mut a[i].vec[j].coeffs[ctr..], KYBER_N - ctr, &buf, XOF_BLOCKBYTES);
      }
    }
  }
}

// Name:        indcpa_keypair
//
// Description: Generates public and private key for the CPA-secure
//              public-key encryption scheme underlying Kyber
//
// Arguments:   - unsigned char *pk: pointer to output public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
//              - unsigned char *sk: pointer to output private key (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
pub fn indcpa_keypair<R>(pk : &mut[u8], sk: &mut[u8], seed: Option<([u8;32], [u8;32])>, rng: &mut R)
-> Result<(), KyberError>
  where R: CryptoRng + RngCore
{
  let mut a = [Polyvec::new(); KYBER_K];
  let (mut e, mut pkpv, mut skpv) = (Polyvec::new(), Polyvec::new(), Polyvec::new());
  let mut nonce = 0u8;
  let mut buf = [0u8; 2*KYBER_SYMBYTES];
  let mut randbuf = [0u8; 2*KYBER_SYMBYTES];

  match seed {
    None => randombytes(&mut randbuf, KYBER_SYMBYTES, rng)?,
    Some(s) => randbuf[..KYBER_SYMBYTES].copy_from_slice(&s.0)
  }
  
  hash_g(&mut buf, &randbuf, KYBER_SYMBYTES);

  let (publicseed, noiseseed) = buf.split_at(KYBER_SYMBYTES);
  gen_a(&mut a, publicseed);

  for i in 0..KYBER_K {
    poly_getnoise_eta1(&mut skpv.vec[i], noiseseed, nonce);
    nonce += 1;
  }
  for i in 0..KYBER_K {
    poly_getnoise_eta1(&mut e.vec[i], noiseseed, nonce);
    nonce += 1;
  }
  
  polyvec_ntt(&mut skpv);
  polyvec_ntt(&mut e);

  // matrix-vector multiplication
  for i in 0..KYBER_K {
    polyvec_pointwise_acc(&mut pkpv.vec[i], &a[i], &skpv);
    poly_frommont(&mut pkpv.vec[i]);
  }
  polyvec_add(&mut pkpv, &e);
  polyvec_reduce(&mut pkpv);

  pack_sk(sk, &mut skpv);
  pack_pk(pk, &mut pkpv, publicseed);
  Ok(())
}

// Name:        indcpa_enc
//
// Description: Encryption function of the CPA-secure
//              public-key encryption scheme underlying Kyber.
//
// Arguments:   - unsigned char *c:          pointer to output ciphertext (of length KYBER_INDCPA_BYTES bytes)
//              - const unsigned char *m:    pointer to input message (of length KYBER_INDCPA_MSGBYTES bytes)
//              - const unsigned char *pk:   pointer to input public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
//              - const unsigned char *coin: pointer to input random coins used as seed (of length KYBER_SYMBYTES bytes)
//                                           to deterministically generate all randomness
pub fn indcpa_enc(c: &mut[u8], m: &[u8], pk: &[u8], coins: &[u8])
{
  let mut at = [Polyvec::new(); KYBER_K];
  let (mut sp, mut pkpv, mut ep, mut bp) = (Polyvec::new(),Polyvec::new(), Polyvec::new(), Polyvec::new());
  let (mut v, mut k, mut epp) = (Poly::new(), Poly::new(), Poly::new());
  let mut seed = [0u8; KYBER_SYMBYTES];
  let mut nonce = 0u8;
  
  unpack_pk(&mut pkpv, &mut seed, pk);
  poly_frommsg(&mut k, m);
  gen_at(&mut at, &seed);

  for i in 0..KYBER_K {
    poly_getnoise_eta1(&mut sp.vec[i], coins, nonce);
    nonce += 1;
  }
  for i in 0..KYBER_K {
    poly_getnoise_eta2(&mut ep.vec[i], coins, nonce);
    nonce += 1;
  }
  poly_getnoise_eta2(&mut epp, coins, nonce);

  polyvec_ntt(&mut sp);

  // matrix-vector multiplication
  for i in 0..KYBER_K {    
    polyvec_pointwise_acc(&mut bp.vec[i], &at[i], &sp);
  }

  polyvec_pointwise_acc(&mut v, &pkpv, &sp);

  polyvec_invntt(&mut bp);
  poly_invntt(&mut v);

  polyvec_add(&mut bp, &ep);
  poly_add(&mut v, &epp);
  poly_add(&mut v, &k);
  polyvec_reduce(&mut bp);
  poly_reduce(&mut v);

  pack_ciphertext(c, &mut bp, &mut v);
}

// Name:        indcpa_dec
//
// Description: Decryption function of the CPA-secure
//              public-key encryption scheme underlying Kyber.
//
// Arguments:   - unsigned char *m:        pointer to output decrypted message (of length KYBER_INDCPA_MSGBYTES)
//              - const unsigned char *c:  pointer to input ciphertext (of length KYBER_INDCPA_BYTES)
//              - const unsigned char *sk: pointer to input secret key (of length KYBER_INDCPA_SECRETKEYBYTES)
pub fn indcpa_dec(m: &mut[u8], c: &[u8], sk: &[u8])
{
  let (mut bp, mut skpv) = (Polyvec::new(),Polyvec::new());
  let (mut v, mut mp) = (Poly::new(),Poly::new());
 
  unpack_ciphertext(&mut bp, &mut v, c);
  unpack_sk(&mut skpv, sk);

  polyvec_ntt(&mut bp);
  polyvec_pointwise_acc(&mut mp, &skpv, &bp);
  poly_invntt(&mut mp);

  poly_sub(&mut mp, &v);
  poly_reduce(&mut mp);

  poly_tomsg(m, &mut mp);
}