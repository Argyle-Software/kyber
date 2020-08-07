use std::error::Error;

#[derive(Debug)]
pub enum KyberError {
  EncodeFail,
  DecodeFail,
  Rng(rand::Error)
}

impl std::fmt::Display for KyberError {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    match *self {
      KyberError::EncodeFail => write!(f, "Encoding Failure"),
      KyberError::DecodeFail => write!(f, "Decode Failure"),
      KyberError::Rng(ref e) => e.fmt(f)
    }
  }
}

impl Error for KyberError {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    match *self {
      KyberError::EncodeFail => None,
      KyberError::DecodeFail => None,
      KyberError::Rng(ref e) => Some(e)
    }
  }
}

// Implement From trait for KyberError wrapper over rand failures.
impl From<rand::Error> for KyberError {
  fn from(err: rand::Error) -> KyberError {
    KyberError::Rng(err)
  }
}

