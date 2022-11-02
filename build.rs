fn main() {
    #[cfg(not(feature = "wasm"))]
    {
        #[cfg(feature = "avx2")]
        {
            const ROOT: &str = "src/avx2/";
            const FILES: [&str; 5] = ["basemul.S", "fq.S", "invntt.S", "ntt.S", "shuffle.S"];

            let paths = FILES.iter().map(|name| format!("{}{}", ROOT, name));
            cc::Build::new()
                .include(ROOT)
                .files(paths)
                .compile("pqc_kyber");
        }
    }
}
