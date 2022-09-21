

fn main() {

  #[cfg(not(any(feature = "reference", feature = "wasm")))]
  #[cfg(target_feature = "avx2")]
  // #[cfg(all(target_arch = "x86_64"))] 
  {
    const ROOT: &str = "src/avx2/";
    const FILES: [&str; 5] = ["basemul.S", "fq.S", "invntt.S", "ntt.S", "shuffle.S"];

    // Separate asm files export underscored symbols for Apple and 32 bit Windows
    fn filepath(name: &str) -> String {
      if cfg!(
        any(
          target = "i686-pc-windows-gnu", 
          target = "i686-pc-windows-msvc",
          vendor = "apple",
        )
      ) 
      {
        format!("_{}{}", ROOT, name) 
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