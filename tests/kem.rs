use pqc_kyber::*;

#[test]
fn keypair_encap_decap() {
  let mut rng = rand::thread_rng();
  let keys = keypair(&mut rng);
  let (ct, ss1) = encapsulate(&keys.public, &mut rng).unwrap();
  let ss2 = decapsulate(&ct, &keys.secret).unwrap();
  assert_eq!(ss1, ss2);
}

#[test]
fn keypair_encap_decap_invalid_ciphertext() {
  let mut rng = rand::thread_rng();
  let keys = keypair(&mut rng);
  let (mut ct, ss) = encapsulate(&keys.public, &mut rng).unwrap();
  ct[..4].copy_from_slice(&[255u8;4]); 
  assert!(decapsulate(&ct, &keys.secret).unwrap() != ss);
}

#[test]
fn keypair_encap_pk_wrong_size() {
  let mut rng = rand::thread_rng();
  let pk: [u8; KYBER_PUBLICKEYBYTES + 3] = [1u8; KYBER_PUBLICKEYBYTES + 3];
  assert!(encapsulate(&pk, &mut rng).is_err());
}

#[test]
fn keypair_decap_ct_wrong_size() {
  let ct: [u8; KYBER_CIPHERTEXTBYTES + 3] = [1u8; KYBER_CIPHERTEXTBYTES + 3];
  let sk: [u8; KYBER_SECRETKEYBYTES] = [1u8; KYBER_SECRETKEYBYTES];
  assert!(decapsulate(&ct, &sk).is_err());
}

#[test]
fn keypair_decap_sk_wrong_size() {
  let ct: [u8; KYBER_CIPHERTEXTBYTES] = [1u8; KYBER_CIPHERTEXTBYTES];
  let sk: [u8; KYBER_SECRETKEYBYTES + 3] = [1u8; KYBER_SECRETKEYBYTES + 3];
  assert!(decapsulate(&ct, &sk).is_err());
}
