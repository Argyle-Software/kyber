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
  let (mut ct, _) = encapsulate(&keys.public, &mut rng).unwrap();
  ct[..4].copy_from_slice(&[255u8;4]); 
  assert!(decapsulate(&ct, &keys.secret).is_err());
}



