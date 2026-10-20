use std::time::Duration;

use application::ports::Clock;
use domain::Timestamp;
use tokio::time::Instant;

/// Instante (epoch) en el que arranca todo `TestClock`.
pub const BASE_EPOCH_SECS: u64 = 1_800_000_000;

/// Reloj de pruebas sobre el tiempo de tokio. Con `#[tokio::test(start_paused = true)]`
/// el tiempo solo avanza cuando el runtime esta ocioso o cuando un test llama a `advance`.
#[derive(Debug, Clone, Copy)]
pub struct TestClock {
    start: Instant,
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl TestClock {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Igual que `Clock::now`, sin necesidad de importar el trait.
    pub fn now(&self) -> Timestamp {
        Timestamp::from_secs(BASE_EPOCH_SECS + self.start.elapsed().as_secs())
    }

    /// Tiempo simulado transcurrido desde la creacion del reloj.
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Deja pasar `d` de tiempo simulado; el resto de tareas progresan mientras tanto.
    pub async fn advance(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        TestClock::now(self)
    }

    async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}
