
#[derive(Debug, PartialEq)]
/// Error types for the various failure modes
pub enum KyberError {
  /// Decapsulation errors occur with a malformed ciphertext or incorrect keypair,
  /// key exchange should be re-attempted
  Decapsulation,
  /// Encapsulation has been given an incorrectly sized public key
  PublicKeyLength,
  /// Decapsulation has been given an incorrectly sized secret key
  SecretKeyLength,
  /// Decapsulation has been given an incorrectly sized ciphertext
  CipherTextLength
}

impl core::fmt::Display for KyberError {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    match *self {
      KyberError::Decapsulation => write!(f, "Decapsulation of Ciphertext Failed"),
      KyberError::PublicKeyLength => write!(f, "Incorrect Public Key Byte Length"),
      KyberError::SecretKeyLength => write!(f, "Incorrect Secret Key Byte Length"),
      KyberError::CipherTextLength => write!(f, "Incorrect Ciphertext Byte Length"),
    }
  }
}
