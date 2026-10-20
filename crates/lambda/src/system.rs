//! Reloj y aleatoriedad reales.

use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use application::ports::{Clock, RandomGenerator};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use domain::Timestamp;

/// Origen de `Clock::monotonic`: el primer uso.
static MONOTONIC_ORIGIN: LazyLock<Instant> = LazyLock::new(Instant::now);

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_secs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
    }

    fn monotonic(&self) -> Duration {
        MONOTONIC_ORIGIN.elapsed()
    }

    async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}

/// CSPRNG del sistema (aws-lc-rs).
#[derive(Debug, Default)]
pub struct OsRng(SystemRandom);

impl OsRng {
    fn fill(&self, buf: &mut [u8]) {
        // Sin aleatoriedad del sistema no hay IDs impredecibles: mejor abortar la invocacion
        // que emitir una sesion adivinable.
        #[allow(clippy::expect_used)]
        self.0.fill(buf).expect("el CSPRNG del sistema fallo");
    }
}

impl RandomGenerator for OsRng {
    fn bytes32(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.fill(&mut b);
        b
    }

    fn below(&self, upper: u64) -> u64 {
        if upper <= 1 {
            return 0;
        }
        // Rechazo para evitar el sesgo del modulo.
        let zone = u64::MAX - (u64::MAX % upper);
        loop {
            let mut b = [0u8; 8];
            self.fill(&mut b);
            let v = u64::from_le_bytes(b);
            if v < zone {
                return v % upper;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aleatorio() {
        let r = OsRng::default();
        assert_ne!(r.bytes32(), r.bytes32());
        assert!((0..1000).all(|_| r.below(7) < 7));
        assert_eq!(r.below(1), 0);
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn reloj() {
        assert!(SystemClock.now().as_secs() > 1_700_000_000);
        let a = SystemClock.monotonic();
        assert!(SystemClock.monotonic() >= a);
    }
}
