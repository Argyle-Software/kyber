use kyber::*;

pub const KEX_UAKE_SENDABYTES: usize = KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES;
pub const KEX_UAKE_SENDBBYTES: usize = KYBER_CIPHERTEXTBYTES;

pub const KEX_AKE_SENDABYTES: usize = KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES;
pub const KEX_AKE_SENDBBYTES: usize = 2 * KYBER_CIPHERTEXTBYTES;

pub const KEX_SSBYTES: usize = KYBER_SSBYTES;

// Perform unilaterally authenticated key exchange
#[test]
fn uake() {
  let mut eska = [0u8; KYBER_SECRETKEYBYTES];

  let mut uake_senda = [0u8; KEX_UAKE_SENDABYTES];
  let mut uake_sendb = [0u8; KEX_UAKE_SENDBBYTES];

  let mut tk = [0u8; KEX_SSBYTES];
  let mut ka = [0u8; KEX_SSBYTES];
  let mut kb = [0u8; KEX_SSBYTES];

  // let alice_keys = keypair();
  let bob_keys = keypair();

  // Alice
  uake_init_a(
    &mut uake_senda, 
    &mut tk, 
    &mut eska, 
    &bob_keys.pubkey
  );
  // Bob
  uake_shared_b(
    &mut uake_sendb, 
    &mut kb, 
    &uake_senda, 
    &bob_keys.secret
  ).unwrap();
  // Alice
  uake_shared_a(
    &mut ka, 
    &uake_sendb, 
    &tk, 
    &eska
  ).unwrap();

  assert_eq!(ka, kb);
}

// Perform mutually authenticated key exchange
#[test]
fn ake() {
  let mut eska = [0u8; KYBER_SECRETKEYBYTES];

  let mut ake_senda = [0u8; KEX_AKE_SENDABYTES];
  let mut ake_sendb = [0u8; KEX_AKE_SENDBBYTES];

  let mut tk = [0u8; KEX_SSBYTES];
  let mut ka = [0u8; KEX_SSBYTES];
  let mut kb = [0u8; KEX_SSBYTES];

  let alice_keys = keypair();
  let bob_keys = keypair();

    // Alice
    ake_init_a(
      &mut ake_senda, 
      &mut tk, 
      &mut eska, 
      &bob_keys.pubkey
    );
    // Bob
    ake_shared_b(
      &mut ake_sendb, 
      &mut kb, 
      &ake_senda, 
      &bob_keys.secret,
      &alice_keys.pubkey
    ).unwrap();
    // Alice
    ake_shared_a(
      &mut ka, 
      &ake_sendb, 
      &tk, 
      &eska,
      &alice_keys.secret
    ).unwrap();
  
    assert_eq!(ka, kb);
}