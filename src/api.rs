use crate::{
  params::*,
  rng::*,
  symmetric::*,
  verify::*,
  indcpa::*
};

pub const CRYPTO_SECRETKEYBYTES: usize =  KYBER_SECRETKEYBYTES;
pub const CRYPTO_PUBLICKEYBYTES: usize =  KYBER_PUBLICKEYBYTES;
pub const CRYPTO_CIPHERTEXTBYTES: usize = KYBER_CIPHERTEXTBYTES;
pub const CRYPTO_BYTES: usize =           KYBER_SSBYTES;

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/

// Todo: return result
pub fn crypto_kem_keypair(pk: &mut[u8], sk: &mut[u8])
{
  indcpa_keypair(pk, sk);
  let end = KYBER_INDCPA_PUBLICKEYBYTES + KYBER_INDCPA_SECRETKEYBYTES;
  sk[KYBER_INDCPA_SECRETKEYBYTES..end].clone_from_slice(&pk[..KYBER_INDCPA_PUBLICKEYBYTES]);
  hash_h(&mut sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES..], pk, KYBER_PUBLICKEYBYTES);
  randombytes(&mut sk[KYBER_SECRETKEYBYTES-KYBER_SYMBYTES..]);        /* Value z for pseudo-random output on reject */
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *ct:       pointer to output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *pk: pointer to input public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/

pub fn crypto_kem_enc(ct: &mut[u8], ss: &mut[u8], pk: &[u8])
{
  let mut kr = [0u8; 2*KYBER_SYMBYTES];
  let mut buf = [0u8; 2*KYBER_SYMBYTES];
  let mut randbuf = [0u8; 2*KYBER_SYMBYTES];
  randombytes(&mut randbuf);
  hash_h(&mut buf, &randbuf, KYBER_SYMBYTES);                                        /* Don't release system RNG output */

  hash_h(&mut buf[KYBER_SYMBYTES..], pk, KYBER_PUBLICKEYBYTES);                    /* Multitarget countermeasure for coins + contributory KEM */
  hash_g(&mut kr, &buf, 2*KYBER_SYMBYTES);

  indcpa_enc(ct, &buf, pk, &kr[KYBER_SYMBYTES..]);                              /* coins are in kr+KYBER_SYMBYTES */

  hash_h(&mut kr[KYBER_SYMBYTES..], ct, KYBER_CIPHERTEXTBYTES);                    /* overwrite coins in kr with H(c) */
  kdf(ss, &kr, 2*KYBER_SYMBYTES as u64); 
}


/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *ct: pointer to input cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - const unsigned char *sk: pointer to input private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/

pub fn crypto_kem_dec(ss: &mut[u8], ct: &[u8], sk: &mut[u8])
{
  let mut buf = [0u8; 2*KYBER_SYMBYTES];
  let mut kr = [0u8; 2*KYBER_SYMBYTES];
  let mut cmp = [0u8; KYBER_CIPHERTEXTBYTES];
  let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
  pk.copy_from_slice(&sk[KYBER_INDCPA_SECRETKEYBYTES..]);

  indcpa_dec(&mut buf, ct, sk);
  for i in 0..KYBER_SYMBYTES {
    buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i];   /* Save hash by storing H(pk) in sk */
  }
  hash_g(&mut kr, &buf, 2*KYBER_SYMBYTES);

  indcpa_enc(&mut cmp, &buf, &pk, &kr[KYBER_SYMBYTES..]);         /* coins are in kr+KYBER_SYMBYTES */

  let fail = verify(ct, &cmp, KYBER_CIPHERTEXTBYTES);

  hash_h(&mut kr[KYBER_SYMBYTES..], ct, KYBER_CIPHERTEXTBYTES);                    /* overwrite coins in kr with H(c)  */

  cmov(&mut kr, &mut sk[KYBER_SECRETKEYBYTES-KYBER_SYMBYTES..], KYBER_SYMBYTES, fail);  /* Overwrite pre-k with z on re-encryption failure */

  kdf(ss, &kr, 2*KYBER_SYMBYTES as u64);                                           /* hash concatenation of pre-k and H(c) to k */

}
