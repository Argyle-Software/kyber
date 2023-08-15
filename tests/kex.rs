use pqc_kyber::*;
mod utils;
use utils::*;

// Kyber struct uake and ake functions
#[test]
fn uake_valid() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let mut bob = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let server_send = bob
        .server_receive(client_init, &bob_keys.secret, &mut rng)
        .unwrap();
    alice.client_confirm(server_send).unwrap();
    assert_eq!(alice.shared_secret, bob.shared_secret);
}

// Corrupted ciphertext sent to bob, 4 bytes modified
#[test]
fn uake_invalid_client_init_ciphertext() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let mut bob = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let mut client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
    client_init[KYBER_PUBLICKEYBYTES..][..4].copy_from_slice(&[255u8; 4]);
    assert!(!bob
        .server_receive(client_init, &bob_keys.secret, &mut rng)
        .is_err());
    assert_ne!(alice.shared_secret, bob.shared_secret);
}

// Corrupted public key sent to bob, detected by Alice
#[test]
fn uake_invalid_client_init_publickey() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let mut bob = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let mut client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
    client_init[..4].copy_from_slice(&[255u8; 4]);
    let server_send = bob
        .server_receive(client_init, &bob_keys.secret, &mut rng)
        .unwrap();
    assert!(!alice.client_confirm(server_send).is_err());
    assert_ne!(alice.shared_secret, bob.shared_secret);
}

// Corrupted ciphertext sent back to Alice
#[test]
fn uake_invalid_server_send_ciphertext() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let mut bob = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let mut server_send = bob
        .server_receive(client_init, &bob_keys.secret, &mut rng)
        .unwrap();
    server_send[..4].copy_from_slice(&[255u8; 4]);
    assert!(!alice.client_confirm(server_send).is_err());
    assert_ne!(alice.shared_secret, bob.shared_secret);
}

// Same tests for AKE

#[test]
fn ake_valid() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let server_send = bob
        .server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)
        .unwrap();
    let _client_confirm = alice
        .client_confirm(server_send, &alice_keys.secret)
        .unwrap();
    assert_eq!(alice.shared_secret, bob.shared_secret);
}

#[test]
fn ake_invalid_client_init_ciphertext() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let mut client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
    client_init[KYBER_PUBLICKEYBYTES..][..4].copy_from_slice(&[255u8; 4]);
    assert!(!bob
        .server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)
        .is_err());
    assert_ne!(alice.shared_secret, bob.shared_secret);
}

#[test]
fn ake_invalid_client_init_publickey() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let mut client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
    client_init[..4].copy_from_slice(&[255u8; 4]);
    let server_send = bob
        .server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)
        .unwrap();
    assert!(!alice
        .client_confirm(server_send, &alice_keys.secret)
        .is_err());
    assert_ne!(alice.shared_secret, bob.shared_secret);
}

#[test]
fn ake_invalid_server_send_first_ciphertext() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let mut server_send = bob
        .server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)
        .unwrap();
    server_send[..4].copy_from_slice(&[255u8; 4]);
    assert!(!alice
        .client_confirm(server_send, &alice_keys.secret)
        .is_err());
    assert_ne!(alice.shared_secret, bob.shared_secret);
}

#[test]
fn ake_invalid_server_send_second_ciphertext() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let mut server_send = bob
        .server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)
        .unwrap();
    server_send[KYBER_CIPHERTEXTBYTES..][..4].copy_from_slice(&[255u8; 4]);
    // assert!(alice.client_confirm(server_send, &alice_keys.secret).is_err());
}

// Rng function fails on keypair
#[test]
fn ake_uake_failed_randombytes_keypair() {
    let mut rng = FailingRng::default();
    assert_eq!(keypair(&mut rng), Err(KyberError::RandomBytesGeneration));
}

// Rng function fails on Alice's client init function
#[test]
fn uake_failed_randombytes_client_init() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let mut rng = FailingRng::default();
    assert_eq!(
        alice.client_init(&bob_keys.public, &mut rng),
        Err(KyberError::RandomBytesGeneration)
    );
}

// Rng function fails on Bob's server receive function
#[test]
fn uake_failed_randombytes_server_receive() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let mut bob = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let mut rng = FailingRng::default();
    assert_eq!(
        bob.server_receive(client_init, &bob_keys.secret, &mut rng),
        Err(KyberError::RandomBytesGeneration)
    );
}

#[test]
fn ake_failed_randombytes_client_init() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let mut rng = FailingRng::default();
    assert_eq!(
        alice.client_init(&bob_keys.public, &mut rng),
        Err(KyberError::RandomBytesGeneration)
    );
}

#[test]
fn ake_failed_randombytes_server_receive() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let mut rng = FailingRng::default();
    assert_eq!(
        bob.server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng),
        Err(KyberError::RandomBytesGeneration)
    )
}
