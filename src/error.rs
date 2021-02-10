
#[derive(Debug, PartialEq)]
/// Error type for the various failure modes
pub enum KyberError {
  Encapsulation,
  Decapsulation,
  Rng
}

impl core::fmt::Display for KyberError {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    match *self {
      KyberError::Encapsulation => write!(f, "Encapsulation Failure"),
      KyberError::Decapsulation => write!(f, "Decapsulation Failure"),
      KyberError::Rng => write!(f, "RNG Failure"),
    }
  }
}
