
#[derive(Debug, PartialEq)]
/// Error type for the various failure modes
pub enum KyberError {
  InvalidInput,
  Encapsulation,
  Decapsulation,
  Rng
}

impl core::fmt::Display for KyberError {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    match *self {
      KyberError::InvalidInput => write!(f, "Function input is of incorrect length"),
      KyberError::Encapsulation => write!(f, "Encapsulation Failure"),
      KyberError::Decapsulation => write!(f, "Decapsulation Failure, unable to obtain shared secret from ciphertext"),
      KyberError::Rng => write!(f, "RNG Failure"),
    }
  }
}
