use std::sync::atomic::{AtomicU64, Ordering};

use application::ports::RandomGenerator;

use crate::util::digest;

/// Generador determinista: `bytes32` es SHA-256(semilla || contador), asi que nunca repite
/// 32 bytes dentro de una instancia. NO es un CSPRNG.
#[derive(Debug)]
pub struct TestRng {
    seed: u64,
    counter: AtomicU64,
}

impl Default for TestRng {
    fn default() -> Self {
        Self::new(0)
    }
}

impl TestRng {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            counter: AtomicU64::new(0),
        }
    }

    fn next(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

impl RandomGenerator for TestRng {
    fn bytes32(&self) -> [u8; 32] {
        digest(&[b"test-rng", &self.seed.to_be_bytes(), &self.next().to_be_bytes()])
    }

    fn below(&self, upper: u64) -> u64 {
        let upper = upper.max(1);
        let mut z = self
            .seed
            .wrapping_add(self.next().wrapping_mul(0x9E37_79B9_7F4A_7C15));
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        (z ^ (z >> 31)) % upper
    }
}
