use std::time::Duration;

/// Instante en segundos desde epoch (UTC). Es la unidad que se guarda en `DynamoDB` y la que
/// devuelve el puerto `Clock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Suma saturada: un TTL enorme nunca da la vuelta a un instante pasado.
    #[must_use]
    pub const fn saturating_add(self, d: Duration) -> Self {
        Self(self.0.saturating_add(d.as_secs()))
    }

    /// Tiempo desde `earlier` hasta `self`; cero si `earlier` es posterior.
    pub const fn saturating_since(self, earlier: Self) -> Duration {
        Duration::from_secs(self.0.saturating_sub(earlier.0))
    }
}
