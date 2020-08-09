use std::fs::File;
use std::path::PathBuf;
use std::io::{prelude::*, BufReader};

#[derive(Debug)]
// Known Answer Tests
pub struct Kat {
  pub count: String,
  pub seed: String,
  pub pk: String,
  pub sk: String,
  pub ct: String,
  pub ss: String
}

impl From<&[String]> for Kat {
  fn from(kat: &[String]) -> Self {
    // Extract values from key:value lines
    let values: Vec<String> = kat.iter()
                .map(|kvs| 
                  {
                    if kvs.len() > 1 {
                      let kv: Vec<&str>  = kvs.split(" = ").collect();
                      kv[1].into()
                    } else {
                      "".into()
                    }
                  }
                ).collect();
    // Build KAT from values
    Kat{
      count: values[0].clone(),
      seed: values[1].clone(),
      pk: values[2].clone(),
      sk: values[3].clone(),
      ct: values[4].clone(),
      ss: values[5].clone(),
    }
  }
}

fn decode_hex(s: &str) -> Vec<u8> {
  (0..s.len())
      .step_by(2)
      .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("Parsing hex string"))
      .collect::<Vec<u8>>()
}

// Get correct buffer filename based on security level chosen
fn get_filename() -> String {
  let filename = if cfg!(feature = "kyber764") {
    "PQCkemKAT_2400.rsp"
  } else {"PQCkemKAT_2400.rsp"};
  filename.into()
}

fn get_filepath() -> PathBuf {
  let mut path = get_test_dir();
  let filename = get_filename();
  path.extend(&[filename]);
  path
}

fn get_test_dir() -> PathBuf {
  let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  path.extend(&["tests"]);
  path
}

fn load_file(filepath: PathBuf) -> File {
  File::open(filepath).expect("Error loading file")
}

fn parse_lines() -> Vec<String> {
  let filepath = get_filepath();
  let file = load_file(filepath);
  let buf = BufReader::new(file);
  //skip file heading ie. "kyber512\n"
  buf.lines()
      .skip(2)
      .map(|l| l.expect("Unable to parse line"))
      .collect()
}

// Packs rsp lines into Kat structs 
pub fn build_kats() -> Vec<Kat> {
  let lines = parse_lines();
  let kats = lines.chunks_exact(7);
  kats.map(|c| {
          let ca = c;
          let cb = ca.into();
          cb
          }
        )
        .collect::<Vec<Kat>>()
}

fn get_encode_buf_strings() -> Vec<String> {
  let mut path = get_test_dir();
  path.extend(&["rand_bufs", "outputs","encode_buffers"]);
  let file = load_file(path);
  let buf = BufReader::new(file);
  buf.lines()
      .map(|l| l.expect("Parsing lines"))
      .collect()
}

pub fn get_encode_buffers() -> Vec<[u8;32]> {
  let buf_strings = get_encode_buf_strings();
  let mut bufs = Vec::new();
  for s in buf_strings {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&decode_hex(&s));
    bufs.push(buf)
  }
  bufs
}

fn get_keypair_buffer_strings() -> Vec<(String, String)> {
  let mut indcpa_path = get_test_dir();
  indcpa_path.extend(&["rand_bufs", "outputs"]);
  let mut crypto_kem_path = indcpa_path.clone();
  indcpa_path.extend(&["indcpa_keypair"]);
  crypto_kem_path.extend(&["crypto_kem_keypair"]);
  let indcpa_file = load_file(indcpa_path);
  let crypto_kem_file = load_file(crypto_kem_path);
  let incpa_buf = BufReader::new(indcpa_file);
  let crypto_kem_buf = BufReader::new(crypto_kem_file);
  incpa_buf.lines()
            .map(|s| s.unwrap())
            .zip(crypto_kem_buf.lines().map(|s| s.unwrap()))
            .collect()
}

pub fn get_keypair_buffers() -> Vec<([u8;32], [u8;32])> {
  let buf_strings = get_keypair_buffer_strings();
  buf_strings.iter()
  .map(|s| 
    { 
      let mut buf1 = [0u8; 32];
      let mut buf2 = [0u8; 32];
      buf1.copy_from_slice(&decode_hex(&s.0));
      buf2.copy_from_slice(&decode_hex(&s.1));
      (buf1, buf2)
    }
  ).collect()
} 