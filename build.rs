fn main() {
  #[cfg(not(feature = "wasm"))]
  {
    #[cfg(feature = "avx2")]
    {
      
      const FILES: [&str; 5] = ["basemul", "fq", "invntt", "ntt", "shuffle"];

      #[cfg(feature = "nasm")]
      {
        const ROOT: &str = "src/avx2/nasm/";
        let paths = FILES.iter().map(|file| format!("{}{}.asm", ROOT, file));

        let mut nasm = nasm_rs::Build::new();
        let mut linker = cc::Build::new();

        nasm.files(paths);
        nasm.include(ROOT);

        for o in  nasm.compile_objects().expect("
          Compiling NASM files: 
          Ensure it is installed and in your path
          https://www.nasm.us/"
        ) {
          linker.object(o);
        }
        linker.compile("pqc_kyber");
      }

      #[cfg(not(feature = "nasm"))]
      {
        const ROOT: &str = "src/avx2/";
        let paths = FILES.iter().map(|file| format!("{}{}.S", ROOT, file));
        cc::Build::new()
          .include(ROOT)
          .files(paths)
          .compile("pqc_kyber");
      }
    }
  }
}