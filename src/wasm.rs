#![allow(non_snake_case)]
extern crate alloc;

use super::*;
use crate::params::*;
use alloc::boxed::Box;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn keypair() -> Result<Keys, JsError>  {
  let mut rng = rand::rngs::OsRng{};
  match api::keypair(&mut rng) {
    Ok(keys) => Ok(Keys{
      pubkey: Box::new(keys.public),
      secret: Box::new(keys.secret)
    }),
    Err(KyberError::RandomBytesGeneration) => Err(JsError::new("Error trying to fill random bytes")),
    _ => Err(JsError::new("The keypair could not be generated"))
  }
}

#[wasm_bindgen]
pub fn encapsulate(pk: Box<[u8]>) -> Result<Kex, JsValue> {
  if pk.len() != KYBER_PUBLICKEYBYTES {
    return Err(JsValue::null())
  }

  let mut rng = rand::rngs::OsRng{};
  match api::encapsulate(&pk, &mut rng) {
    Ok(kex) => Ok(Kex {
      ciphertext: Box::new(kex.0),
      sharedSecret: Box::new(kex.1)
    }),
    Err(_) => Err(JsValue::null())
  }
}

#[wasm_bindgen]
pub fn decapsulate(ct: Box<[u8]>, sk: Box<[u8]>) -> Result<Box<[u8]>, JsValue> {
  if ct.len() != KYBER_CIPHERTEXTBYTES || sk.len() != KYBER_SECRETKEYBYTES {
    return Err(JsValue::null())
  }

  match api::decapsulate(&ct, &sk) {
    Ok(ss) => Ok(Box::new(ss)),
    Err(_) => Err(JsValue::null())
  }
}

#[wasm_bindgen]
pub struct Keys{
  pubkey: Box<[u8]>,
  secret: Box<[u8]>,
}

#[wasm_bindgen]
pub struct Kex{
  ciphertext: Box<[u8]>,
  sharedSecret: Box<[u8]>,
}

#[wasm_bindgen]
impl Keys {
  #[wasm_bindgen(constructor)]
  pub fn new() -> Result<Keys, JsError> {
    keypair()
  }

  #[wasm_bindgen(getter)]
  pub fn pubkey(&self) -> Box<[u8]> {
    self.pubkey.clone()
  }

  #[wasm_bindgen(getter)]
  pub fn secret(&self) -> Box<[u8]> {
    self.secret.clone()
  }
}

#[wasm_bindgen]
impl Kex {
  #[wasm_bindgen(constructor)]
  pub fn new(public_key: Box<[u8]>) -> Self {
    encapsulate(public_key).expect("Invalid Public Key Size")
  }

  #[wasm_bindgen(getter)]
  pub fn ciphertext(&self) -> Box<[u8]> {
    self.ciphertext.clone()
  }

  #[wasm_bindgen(getter)]
  pub fn sharedSecret(&self) -> Box<[u8]> {
    self.sharedSecret.clone()
  }

  #[wasm_bindgen(setter)]
  pub fn set_ciphertext(&mut self, ciphertext: Box<[u8]>) {
    self.ciphertext = ciphertext;
  }

  #[wasm_bindgen(setter)]
  pub fn set_sharedSecret(&mut self, sharedSecret: Box<[u8]>) {
    self.sharedSecret = sharedSecret;
  }
}

#[wasm_bindgen]
pub struct Params {
  #[wasm_bindgen(readonly)]
  pub publicKeyBytes: usize,
  #[wasm_bindgen(readonly)]
  pub secretKeyBytes: usize,
  #[wasm_bindgen(readonly)]
  pub ciphertextBytes: usize,
  #[wasm_bindgen(readonly)]
  pub sharedSecretBytes: usize,
}

#[wasm_bindgen]
impl Params {
  #[wasm_bindgen(getter)]
  pub fn publicKeyBytes() -> usize {
    KYBER_PUBLICKEYBYTES
  }

  #[wasm_bindgen(getter)]
  pub fn secretKeyBytes() -> usize {
    KYBER_SECRETKEYBYTES
  }
  
  #[wasm_bindgen(getter)]
  pub fn ciphertextBytes() -> usize {
    KYBER_CIPHERTEXTBYTES
  }

  #[wasm_bindgen(getter)]
  pub fn sharedSecretBytes() -> usize {
    KYBER_SSBYTES
  }
}
