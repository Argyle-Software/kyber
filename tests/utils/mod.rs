use rand_core::{CryptoRng, Error, RngCore};

pub struct FailingRng(u64);

impl Default for FailingRng {
    fn default() -> Self {
        Self(0)
    }
}

impl RngCore for FailingRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {}

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::new(
            "Error filling bytes with random numbers generated from an external True RNG device",
        ))
    }
}

impl CryptoRng for FailingRng {}
