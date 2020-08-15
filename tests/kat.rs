mod load;

use load::*;
use kyber::{*, utils::decode_hex};

// Generate KAT keypairs from seeds.
#[test]
#[cfg(feature="KATs")]
fn keypairs() {
  let kats = build_kats();
  let keypair_bufs = get_keypair_bufs();
  for (i, kat) in kats.iter().enumerate() {
    let known_pk = decode_hex(&kat.pk);
    let known_sk = decode_hex(&kat.sk);
    let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
    let mut sk = [0u8; KYBER_SECRETKEYBYTES];
    crypto_kem_keypair(&mut pk, &mut sk, Some(keypair_bufs[i]));
    assert_eq!(&pk[..], &known_pk[..], "Public key generation failure");
    assert_eq!(&sk[..], &known_sk[..], "Secret key generation failure");
  }
}

// Encapsulating KAT's using deterministic rand buffers
#[test]
#[cfg(feature="KATs")]
fn encaps() {
  let kats = build_kats();
  let bufs = get_encode_bufs();
  for (i, kat) in kats.iter().enumerate() {
    let known_ct = decode_hex(&kat.ct);
    let known_ss = decode_hex(&kat.ss);
    let pk = decode_hex(&kat.pk);
    let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
    let mut ss = [0u8; KYBER_SSBYTES];
    crypto_kem_enc(&mut ct, &mut ss, &pk, Some(&bufs[i]));
    assert_eq!(&ct[..], &known_ct[..], "Ciphertext creation failure");
    assert_eq!(&ss[..], &known_ss[..], "Shared secret creation failure");
  }
}

// Decapsulating KAT's
#[test]
fn decaps() {
  let kats = build_kats();
  for kat in kats {
    let sk = decode_hex(&kat.sk);
    let ct = decode_hex(&kat.ct);
    let decap_result = decapsulate(&ct, &sk);
    assert!(decap_result.is_ok(), "KEM decasulation failure");
  }
}