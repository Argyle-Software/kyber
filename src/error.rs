use std::error::Error;

#[derive(Debug)]
/// Error type for the various failure modes
pub enum KyberError {
  EncodeFail,
  DecodeFail,
  KeyPair(rand::Error)
}

impl std::fmt::Display for KyberError {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    match *self {
      KyberError::EncodeFail => write!(f, "Encoding Failure"),
      KyberError::DecodeFail => write!(f, "Decode Failure"),
      KyberError::KeyPair(ref e) => e.fmt(f)
    }
  }
}

impl Error for KyberError {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    match *self {
      KyberError::EncodeFail => None,
      KyberError::DecodeFail => None,
      KyberError::KeyPair(ref e) => Some(e)
    }
  }
}

// Implement From trait for KyberError wrapper over rand failures.
impl From<rand::Error> for KyberError {
  fn from(err: rand::Error) -> KyberError {
    KyberError::KeyPair(err)
  }
}

