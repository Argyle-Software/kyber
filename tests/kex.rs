#![cfg(not(feature="KATs"))]
use pqc_kyber::*;

// Kyber struct uake and ake functions
#[test]
fn kyber_uake() {
  let mut rng = rand::thread_rng();
  let mut alice = Uake::new();
  let mut bob = Uake::new();
  let bob_keys = keypair(&mut rng);
  let client_init = alice.client_init(&bob_keys.public, &mut rng);
  let server_send = bob.server_receive(client_init, &bob_keys.secret, &mut rng).unwrap();
  let _client_confirm = alice.client_confirm(server_send).unwrap();
  assert_eq!(alice.shared_secret, bob.shared_secret);
}

#[test]
fn kyber_ake() {
  let mut rng = rand::thread_rng();
  let mut alice = Ake::new();
  let mut bob = Ake::new();
  let alice_keys = keypair(&mut rng);
  let bob_keys = keypair(&mut rng);
  let client_init = alice.client_init(&bob_keys.public, &mut rng);
  let server_send = bob.server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng).unwrap();
  let _client_confirm = alice.client_confirm(server_send, &alice_keys.secret).unwrap();
  assert_eq!(alice.shared_secret, bob.shared_secret);
}

// Low Level Functions

// // Unilaterally authenticated key exchange
// #[test]
// fn low_level_uake() {
//   let mut rng = rand::thread_rng();

//   let mut eska = [0u8; KYBER_SECRETKEYBYTES];

//   let mut uake_senda = [0u8; KEX_UAKE_SENDABYTES];
//   let mut uake_sendb = [0u8; KEX_UAKE_SENDBBYTES];

//   let mut tk = [0u8; KEX_SSBYTES];
//   let mut ka = [0u8; KEX_SSBYTES];
//   let mut kb = [0u8; KEX_SSBYTES];

//   let bob_keys = keypair(&mut rng).unwrap();

//   // Alice
//   uake_init_a(
//     &mut uake_senda, &mut tk, &mut eska, 
//     &bob_keys.public, &mut rng
//   ).unwrap();
//   // Bob
//   uake_shared_b(
//     &mut uake_sendb, &mut kb, &uake_senda, 
//     &bob_keys.secret, &mut rng
//   ).unwrap();
//   // Alice
//   uake_shared_a(&mut ka, &uake_sendb, &tk, &eska).unwrap();

//   assert_eq!(ka, kb);
// }

// // Mutually authenticated key exchange
// #[test]
// fn low_level_ake() {
//   let mut rng = rand::thread_rng();
//   let mut eska = [0u8; KYBER_SECRETKEYBYTES];

//   let mut ake_senda = [0u8; KEX_AKE_SENDABYTES];
//   let mut ake_sendb = [0u8; KEX_AKE_SENDBBYTES];

//   let mut tk = [0u8; KEX_SSBYTES];
//   let mut ka = [0u8; KEX_SSBYTES];
//   let mut kb = [0u8; KEX_SSBYTES];

//   let alice_keys = keypair(&mut rng).unwrap();
//   let bob_keys = keypair(&mut rng).unwrap();

//     // Alice
//     ake_init_a(&mut ake_senda, &mut tk, &mut eska, &bob_keys.public, &mut rng).unwrap();

//     // Bob
//     ake_shared_b(
//       &mut ake_sendb, &mut kb, &ake_senda, &bob_keys.secret,
//       &alice_keys.public, &mut rng
//     ).unwrap();

//     // Alice
//     ake_shared_a(&mut ka, &ake_sendb, &tk, &eska, &alice_keys.secret).unwrap();
  
//     assert_eq!(ka, kb);
// }