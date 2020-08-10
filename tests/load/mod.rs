#![allow(dead_code)]
use kyber::{utils::decode_hex, KYBER_K, KYBER_90S};
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
    let values: Vec<String>;
    values = kat.iter()
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
    Kat {
      count: values[0].clone(),
      seed: values[1].clone(),
      pk: values[2].clone(),
      sk: values[3].clone(),
      ct: values[4].clone(),
      ss: values[5].clone(),
    }
  }
}

// Get KAT filename based on security level
fn get_filename() -> String {
  let mut filename = match KYBER_K {
    2 => "PQCkemKAT_1632".to_string(),
    3 => "PQCkemKAT_2400".to_string(),
    4 => "PQCkemKAT_3168".to_string(),
    _ => panic!("No security level set")
  };
  if KYBER_90S {
    filename.push_str("-90s.rsp");
  } else {
    filename.push_str(".rsp");
  }
  filename
}

fn get_test_dir() -> PathBuf {
  let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  path.extend(&["tests"]);
  path
}

fn get_buffer_filepath(filename: &str) -> PathBuf {
  let mut path = get_test_dir();
  path.extend(&["rand_bufs", "outputs"]);
  path.extend(&[filename]);
  path
}

fn get_kat_filepath() -> PathBuf {
  let mut path = get_test_dir();
  let filename = get_filename();
  path.extend(&["KATs"]);
  path.extend(&[filename]);
  path
}


fn load_file(filepath: PathBuf) -> File {
  File::open(filepath).expect("Error loading file")
}

fn parse_kats() -> Vec<String> {
  let filepath = get_kat_filepath();
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
  let lines = parse_kats();
  let kats = lines.chunks_exact(7);
  // From String slice into Vec<KAT>
  kats.map(|c| {c.into()})
      .collect::<Vec<Kat>>()
}

fn get_encode_buf_strings() -> Vec<String> {
  let path = get_buffer_filepath("encode");
  let buf = BufReader::new(load_file(path));
  buf.lines()
      .map(|l| l.expect("Parsing lines"))
      .collect()
}

pub fn get_encode_bufs() -> Vec<[u8;32]> {
  let mut bufs = Vec::new();
  for s in get_encode_buf_strings() {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&decode_hex(&s));
    bufs.push(buf)
  }
  bufs
}

fn get_keypair_buffer_strings() -> Vec<(String, String)> {
  let indcpa_path = get_buffer_filepath("indcpa_keypair");
  let crypto_kem_path = get_buffer_filepath("crypto_kem_keypair");
  let indcpa_file = load_file(indcpa_path);
  let crypto_kem_file = load_file(crypto_kem_path);
  let incpa_buf = BufReader::new(indcpa_file);
  let crypto_kem_buf = BufReader::new(crypto_kem_file);
  incpa_buf.lines()
    .map(|s| s.unwrap())
    // Zip together iterators into a string tuple
    .zip(crypto_kem_buf.lines().map(|s| s.unwrap()))
    .collect()
}

pub fn get_keypair_bufs() -> Vec<([u8;32], [u8;32])> {
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