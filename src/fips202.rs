#![allow(clippy::needless_range_loop)]

const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;
const SHA3_256_RATE: usize = 136;
const SHA3_512_RATE: usize =  72;
const NROUNDS: usize = 24;

fn rol(a: u64, offset: u64) -> u64 
{
  (a << offset) ^ (a >> (64-offset))
}

// Name:        load64
//
// Description: Load 8 bytes into uint64_t in little-endian order
//
// Arguments:   - const unsigned char *x: pointer to input byte array
//
// Returns the loaded 64-bit unsigned integer
pub fn load64(x: &[u8]) -> u64
{
  let mut r = 0u64;
  for i in 0..8 {
    r |= (x[i] as u64) << (8 * i);
  }
  r
}

// Name:        store64
//
// Description: Store a 64-bit integer to a byte array in little-endian order
//
// Arguments:   - uint8_t *x: pointer to the output byte array
//              - uint64_t u: input 64-bit unsigned integer
pub fn store64(x: &mut[u8], mut u: u64)
{
  for i in x.iter_mut().take(8) {
    *i = u as u8;
    u >>= 8;
  }
}

// Keccak round constants
const KECCAKF_ROUNDCONSTANTS: [u64; NROUNDS] = [
  0x0000000000000001,
  0x0000000000008082,
  0x800000000000808a,
  0x8000000080008000,
  0x000000000000808b,
  0x0000000080000001,
  0x8000000080008081,
  0x8000000000008009,
  0x000000000000008a,
  0x0000000000000088,
  0x0000000080008009,
  0x000000008000000a,
  0x000000008000808b,
  0x800000000000008b,
  0x8000000000008089,
  0x8000000000008003,
  0x8000000000008002,
  0x8000000000000080,
  0x000000000000800a,
  0x800000008000000a,
  0x8000000080008081,
  0x8000000000008080,
  0x0000000080000001,
  0x8000000080008008
];

// Name:        KeccakF1600_StatePermute
//
// Description: The Keccak F1600 Permutation
//
// Arguments:   - uint64_t * state: pointer to in/output Keccak state
pub fn keccakf1600_statepermute(state: &mut[u64])
{
  //copyFromState(A, state)
 let mut aba = state[ 0];
 let mut abe = state[ 1];
 let mut abi = state[ 2];
 let mut abo = state[ 3];
 let mut abu = state[ 4];
 let mut aga = state[ 5];
 let mut age = state[ 6];
 let mut agi = state[ 7];
 let mut ago = state[ 8];
 let mut agu = state[ 9];
 let mut aka = state[10];
 let mut ake = state[11];
 let mut aki = state[12];
 let mut ako = state[13];
 let mut aku = state[14];
 let mut ama = state[15];
 let mut ame = state[16];
 let mut ami = state[17];
 let mut amo = state[18];
 let mut amu = state[19];
 let mut asa = state[20];
 let mut ase = state[21];
 let mut asi = state[22];
 let mut aso = state[23];
 let mut asu = state[24];

  for round in (0..NROUNDS).step_by(2) {
    // prepareTheta
    let mut bca = aba^aga^aka^ama^asa;
    let mut bce = abe^age^ake^ame^ase;
    let mut bci = abi^agi^aki^ami^asi;
    let mut bco = abo^ago^ako^amo^aso;
    let mut bcu = abu^agu^aku^amu^asu;

    //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
    let mut da = bcu^rol(bce, 1);
    let mut de = bca^rol(bci, 1);
    let mut di = bce^rol(bco, 1);
    let mut d_o = bci^rol(bcu, 1);
    let mut du = bco^rol(bca, 1);

    aba ^= da;
    bca = aba;
    age ^= de;
    bce = rol(age, 44);
    aki ^= di;
    bci = rol(aki, 43);
    amo ^= d_o;
    bco = rol(amo, 21);
    asu ^= du;
    bcu = rol(asu, 14);
    let mut eba =   bca ^((!bce)&  bci );
    eba ^= KECCAKF_ROUNDCONSTANTS[round];
    let mut ebe =   bce ^((!bci)&  bco );
    let mut ebi =   bci ^((!bco)&  bcu );
    let mut ebo =   bco ^((!bcu)&  bca );
    let mut ebu =   bcu ^((!bca)&  bce );

    abo ^= d_o;
    bca = rol(abo, 28);
    agu ^= du;
    bce = rol(agu, 20);
    aka ^= da;
    bci = rol(aka,  3);
    ame ^= de;
    bco = rol(ame, 45);
    asi ^= di;
    bcu = rol(asi, 61);
    let mut ega =   bca ^((!bce)&  bci );
    let mut ege =   bce ^((!bci)&  bco );
    let mut egi =   bci ^((!bco)&  bcu );
    let mut ego =   bco ^((!bcu)&  bca );
    let mut egu =   bcu ^((!bca)&  bce );

    abe ^= de;
    bca = rol(abe,  1);
    agi ^= di;
    bce = rol(agi,  6);
    ako ^= d_o;
    bci = rol(ako, 25);
    amu ^= du;
    bco = rol(amu,  8);
    asa ^= da;
    bcu = rol(asa, 18);
    let mut eka =   bca ^((!bce)&  bci );
    let mut eke =   bce ^((!bci)&  bco );
    let mut eki =   bci ^((!bco)&  bcu );
    let mut eko =   bco ^((!bcu)&  bca );
    let mut eku =   bcu ^((!bca)&  bce );

    abu ^= du;
    bca = rol(abu, 27);
    aga ^= da;
    bce = rol(aga, 36);
    ake ^= de;
    bci = rol(ake, 10);
    ami ^= di;
    bco = rol(ami, 15);
    aso ^= d_o;
    bcu = rol(aso, 56);
    let mut ema =   bca ^((!bce)&  bci );
    let mut eme =   bce ^((!bci)&  bco );
    let mut emi =   bci ^((!bco)&  bcu );
    let mut emo =   bco ^((!bcu)&  bca );
    let mut emu =   bcu ^((!bca)&  bce );

    abi ^= di;
    bca = rol(abi, 62);
    ago ^= d_o;
    bce = rol(ago, 55);
    aku ^= du;
    bci = rol(aku, 39);
    ama ^= da;
    bco = rol(ama, 41);
    ase ^= de;
    bcu = rol(ase,  2);
    let mut esa =   bca ^((!bce)&  bci );
    let mut ese =   bce ^((!bci)&  bco );
    let mut esi =   bci ^((!bco)&  bcu );
    let mut eso =   bco ^((!bcu)&  bca );
    let mut esu =   bcu ^((!bca)&  bce );

    //    prepareTheta
    bca = eba^ega^eka^ema^esa;
    bce = ebe^ege^eke^eme^ese;
    bci = ebi^egi^eki^emi^esi;
    bco = ebo^ego^eko^emo^eso;
    bcu = ebu^egu^eku^emu^esu;

    //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
    da = bcu^rol(bce, 1);
    de = bca^rol(bci, 1);
    di = bce^rol(bco, 1);
    d_o = bci^rol(bcu, 1);
    du = bco^rol(bca, 1);

    eba ^= da;
    bca = eba;
    ege ^= de;
    bce = rol(ege, 44);
    eki ^= di;
    bci = rol(eki, 43);
    emo ^= d_o;
    bco = rol(emo, 21);
    esu ^= du;
    bcu = rol(esu, 14);
    aba =   bca ^((!bce)&  bci );
    aba ^= KECCAKF_ROUNDCONSTANTS[round+1];
    abe =   bce ^((!bci)&  bco );
    abi =   bci ^((!bco)&  bcu );
    abo =   bco ^((!bcu)&  bca );
    abu =   bcu ^((!bca)&  bce );

    ebo ^= d_o;
    bca = rol(ebo, 28);
    egu ^= du;
    bce = rol(egu, 20);
    eka ^= da;
    bci = rol(eka, 3);
    eme ^= de;
    bco = rol(eme, 45);
    esi ^= di;
    bcu = rol(esi, 61);
    aga =   bca ^((!bce)&  bci );
    age =   bce ^((!bci)&  bco );
    agi =   bci ^((!bco)&  bcu );
    ago =   bco ^((!bcu)&  bca );
    agu =   bcu ^((!bca)&  bce );

    ebe ^= de;
    bca = rol(ebe, 1);
    egi ^= di;
    bce = rol(egi, 6);
    eko ^= d_o;
    bci = rol(eko, 25);
    emu ^= du;
    bco = rol(emu, 8);
    esa ^= da;
    bcu = rol(esa, 18);
    aka =   bca ^((!bce)&  bci );
    ake =   bce ^((!bci)&  bco );
    aki =   bci ^((!bco)&  bcu );
    ako =   bco ^((!bcu)&  bca );
    aku =   bcu ^((!bca)&  bce );

    ebu ^= du;
    bca = rol(ebu, 27);
    ega ^= da;
    bce = rol(ega, 36);
    eke ^= de;
    bci = rol(eke, 10);
    emi ^= di;
    bco = rol(emi, 15);
    eso ^= d_o;
    bcu = rol(eso, 56);
    ama =   bca ^((!bce)&  bci );
    ame =   bce ^((!bci)&  bco );
    ami =   bci ^((!bco)&  bcu );
    amo =   bco ^((!bcu)&  bca );
    amu =   bcu ^((!bca)&  bce );

    ebi ^= di;
    bca = rol(ebi, 62);
    ego ^= d_o;
    bce = rol(ego, 55);
    eku ^= du;
    bci = rol(eku, 39);
    ema ^= da;
    bco = rol(ema, 41);
    ese ^= de;
    bcu = rol(ese, 2);
    asa =   bca ^((!bce)&  bci );
    ase =   bce ^((!bci)&  bco );
    asi =   bci ^((!bco)&  bcu );
    aso =   bco ^((!bcu)&  bca );
    asu =   bcu ^((!bca)&  bce );
  } 

  state[ 0] = aba;
  state[ 1] = abe;
  state[ 2] = abi;
  state[ 3] = abo;
  state[ 4] = abu;
  state[ 5] = aga;
  state[ 6] = age;
  state[ 7] = agi;
  state[ 8] = ago;
  state[ 9] = agu;
  state[10] = aka;
  state[11] = ake;
  state[12] = aki;
  state[13] = ako;
  state[14] = aku;
  state[15] = ama;
  state[16] = ame;
  state[17] = ami;
  state[18] = amo;
  state[19] = amu;
  state[20] = asa;
  state[21] = ase;
  state[22] = asi;
  state[23] = aso;
  state[24] = asu;
}

// Name:        keccak_absorb
//
// Description: Absorb step of Keccak;
//              non-incremental, starts by zeroeing the state.
//
// Arguments:   - uint64_t *s:             pointer to (uninitialized) output Keccak state
//              - unsigned int r:          rate in bytes (e.g., 168 for SHAKE128)
//              - const unsigned char *m:  pointer to input to be absorbed into s
//              - unsigned long long mlen: length of input in bytes
//              - unsigned char p:         domain-separation byte for different Keccak-derived functions
pub fn keccak_absorb(s: &mut[u64], r: usize, m: &[u8], mut mlen: u64, p: u8)
{
  let mut t = [0u8; 200];

  // Zero State
  for i in s.iter_mut() {
    *i = 0;
  }

  let mut idx = 0usize;
  while mlen >= r as u64 {
    for i in 0..(r/8) {
      s[i] ^= load64(&m[idx+8*i..]);
    }
    keccakf1600_statepermute(s);
    mlen -= r as u64;
    idx += r;
  }

  t[..mlen as usize].copy_from_slice(&m[idx..idx+mlen as usize]);
  t[mlen as usize] = p;
  t[r - 1] |= 128;
  for i in 0..(r/8) {
    s[i] ^= load64(&t[8*i..]);
  }
}

// Name:        keccak_squeezeblocks
//
// Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
//              Modifies the state. Can be called multiple times to keep squeezing,
//              i.e., is incremental.
//
// Arguments:   - unsigned char *h:               pointer to output blocks
//              - unsigned long long int nblocks: number of blocks to be squeezed (written to h)
//              - uint64_t *s:                    pointer to in/output Keccak state
//              - unsigned int r:                 rate in bytes (e.g., 168 for SHAKE128)
pub fn keccak_squeezeblocks(h: &mut[u8], mut nblocks: u64, s: &mut [u64], r: usize)
{
  let mut idx = 0usize;
  while nblocks > 0 {
    keccakf1600_statepermute(s);
    for i in 0..(r>>3) {
      store64(&mut h[idx+8*i..], s[i])
    }
    idx += r;
    nblocks -= 1;
  }
}

// Name:        shake128_absorb
//
// Description: Absorb step of the SHAKE128 XOF.
//              non-incremental, starts by zeroeing the state.
//
// Arguments:   - uint64_t *s:                     pointer to (uninitialized) output Keccak state
//              - const unsigned char *input:      pointer to input to be absorbed into s
//              - unsigned long long inputByteLen: length of input in bytes
pub fn shake128_absorb(s: &mut[u64], input: &[u8], inputbyte_len: u64)
{
  keccak_absorb(s, SHAKE128_RATE, input, inputbyte_len, 0x1F);
}



// Name:        shake128_squeezeblocks
//
// Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHAKE128_RATE bytes each.
//              Modifies the state. Can be called multiple times to keep squeezing,
//              i.e., is incremental.
//
// Arguments:   - unsigned char *output:      pointer to output blocks
//              - unsigned long long nblocks: number of blocks to be squeezed (written to output)
//              - uint64_t *s:                pointer to in/output Keccak state
pub fn shake128_squeezeblocks(output: &mut[u8], nblocks: u64, s: &mut[u64])
{
  keccak_squeezeblocks(output, nblocks, s, SHAKE128_RATE);
}

// Name:        shake256
//
// Description: SHAKE256 XOF with non-incremental API
//
// Arguments:   - unsigned char *output:      pointer to output
//              - unsigned long long outlen:  requested output length in bytes
//              - const unsigned char *input: pointer to input
//               - unsigned long long inlen:   length of input in bytes
pub fn shake256(output: &mut[u8], outlen: u64, input: &[u8], inlen: u64)
{
  let mut s = [0u64; 25];
  let mut t = [0u8; SHAKE256_RATE];
  let nblocks = outlen/SHAKE256_RATE as u64;
  
    /* Absorb input */
    keccak_absorb(&mut s, SHAKE256_RATE, input, inlen, 0x1F);

    /* Squeeze output */
    keccak_squeezeblocks(output, nblocks, &mut s, SHAKE256_RATE);
    
    // TODO: redundant array indexing?? outlen never exceeds SHAE256_RATE
    // let mut idx =0;
    // idx += nblocks as usize *SHAKE256_RATE;
    // outlen -= nblocks *SHAKE256_RATE as u64;

    if outlen > 0
    {
      keccak_squeezeblocks(&mut t, 1, &mut s, SHAKE256_RATE);
      output[..outlen as usize].copy_from_slice(&t[..outlen as usize])
    }
}

// Name:        sha3_256
//
// Description: SHA3-256 with non-incremental API
//
// Arguments:   - unsigned char *output:      pointer to output (32 bytes)
//              - const unsigned char *input: pointer to input
//              - unsigned long long inlen:   length of input in bytes
pub fn sha3_256(output: &mut [u8], input: &[u8], inlen: usize)
{
  let mut s =[0u64; 25];
  let mut t = [0u8; SHA3_256_RATE];

  /* Absorb input */
  keccak_absorb(&mut s, SHA3_256_RATE, input, inlen as u64, 0x06);

  /* Squeeze output */
  keccak_squeezeblocks(&mut t, 1, &mut s, SHA3_256_RATE);

  output[..32].copy_from_slice(&t[..32])
}

// Name:        sha3_512
//
// Description: SHA3-512 with non-incremental API
//
// Arguments:   - unsigned char *output:      pointer to output (64 bytes)
//              - const unsigned char *input: pointer to input
//              - unsigned long long inlen:   length of input in bytes
pub fn sha3_512(output: &mut [u8], input: &[u8], inlen: usize) {
  let mut s =[0u64; 25];
  let mut t = [0u8; SHA3_512_RATE];

    /* Absorb input */
    keccak_absorb(&mut s, SHA3_512_RATE, input, inlen as u64, 0x06);

    /* Squeeze output */
    keccak_squeezeblocks(&mut t, 1, &mut s, SHA3_512_RATE);

    output[..64].copy_from_slice(&t[..64])
}
