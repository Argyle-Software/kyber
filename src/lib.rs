#![allow(dead_code, clippy::many_single_char_names, clippy::needless_range_loop)]

mod aes256;
mod api;
mod cbd;
mod fips202;
mod indcpa;
mod params;
mod poly;
mod polyvec;
mod ntt;
mod reduce;
mod rng;
mod sha;
mod symmetric;
mod verify;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
