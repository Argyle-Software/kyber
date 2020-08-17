//! Basic helper functions

// Encodes a byte slice into a hex string
pub fn encode_hex(bytes: &[u8]) -> String {
  let mut output = String::new();
  for b in bytes {
        output.push_str(&format!("{:02X}", b));
    }
  output
}

// Decodes a hex string into a vector of bytes
pub fn decode_hex(s: &str) -> Vec<u8> {
  (0..s.len())
      .step_by(2)
      .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("Hex string decoding"))
      .collect::<Vec<u8>>()
}