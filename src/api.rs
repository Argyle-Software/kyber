use crate::params::*;

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
  indcpa_keypair(&mut pk, &mut sk);
  for i in 0..KYBER_INDCPA_PUBLICKEYBYTES {
    sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
  }
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  randombytes(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);        /* Value z for pseudo-random output on reject */
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
  randombytes(&mut buf, KYBER_SYMBYTES);
  hash_h(&mut buf, &mut buf, KYBER_SYMBYTES);                                        /* Don't release system RNG output */

  hash_h(&mut buf[KYBER_SYMBYTES..], pk, KYBER_PUBLICKEYBYTES);                    /* Multitarget countermeasure for coins + contributory KEM */
  hash_g(&mut kr, &mut buf, 2*KYBER_SYMBYTES);

  indcpa_enc(&mut ct, &mut buf, pk, &kr[KYBER_SYMBYTES..]);                              /* coins are in kr+KYBER_SYMBYTES */

  hash_h(&mut kr[KYBER_SYMBYTES..], ct, KYBER_CIPHERTEXTBYTES);                    /* overwrite coins in kr with H(c) */
  kdf(&mut ss, kr, 2*KYBER_SYMBYTES); 
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

