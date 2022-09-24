

fn main() {

  #[cfg(not(any(feature = "reference", feature = "wasm")))]
  #[cfg(target_feature = "avx2")]
  {
    const ROOT: &str = "src/avx2/";
    const FILES: [&str; 5] = ["basemul.S", "fq.S", "invntt.S", "ntt.S", "shuffle.S"];

    // Separate asm files export underscored symbols for Apple
    // M1 macs cannot use avx instructions
    fn filepath(name: &str) -> String {
      if cfg!(target_vendor = "apple") 
      {
        format!("{}_{}", ROOT, name) 
      } else {
        format!("{}{}", ROOT, name) 
      }
    }

    let paths = FILES.iter().map(|x| filepath(x));
    cc::Build::new()
      .include(ROOT)
      .files(paths)
      .compile("pqc_kyber");
  }
}