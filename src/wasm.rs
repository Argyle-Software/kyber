extern crate alloc;

use super::*;
use alloc::boxed::Box;
use wasm_bindgen::prelude::*;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;



#[wasm_bindgen]
pub fn keypair() -> Keys {
  let mut rng = rand::rngs::OsRng{};
  let keys = api::keypair(&mut rng);
  Keys{
    pubkey: Box::new(keys.public),
    secret: Box::new(keys.secret)
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
      shared_secret: Box::new(kex.1)
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
  shared_secret: Box<[u8]>,
}

#[wasm_bindgen]
impl Keys {
  #[wasm_bindgen(constructor)]
  pub fn new() -> Self {
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

  #[wasm_bindgen(setter)]
  pub fn set_pubkey(&mut self, pubkey: Box<[u8]>) {
    self.pubkey = pubkey;
  }

  #[wasm_bindgen(setter)]
  pub fn set_secret(&mut self, secret: Box<[u8]>) {
    self.secret = secret;
  }
}

#[wasm_bindgen]
impl Kex {
  #[wasm_bindgen(constructor)]
  pub fn new() -> Self {
    Self {
      ciphertext: Box::new([0u8; KYBER_CIPHERTEXTBYTES]),
      shared_secret: Box::new([0u8; KYBER_SSBYTES])
    }
  }

  #[wasm_bindgen(getter)]
  pub fn ciphertext(&self) -> Box<[u8]> {
    self.ciphertext.clone()
  }

  #[wasm_bindgen(getter)]
  pub fn shared_secret(&self) -> Box<[u8]> {
    self.shared_secret.clone()
  }

  #[wasm_bindgen(setter)]
  pub fn set_ciphertext(&mut self, ciphertext: Box<[u8]>) {
    self.ciphertext = ciphertext;
  }

  #[wasm_bindgen(setter)]
  pub fn set_shared_secret(&mut self, shared_secret: Box<[u8]>) {
    self.shared_secret = shared_secret;
  }
}
