use std::time::Duration;

use domain::{PendingPolicy, SessionPolicy, WsTicketPolicy};

/// Tope duro del body reenviado al upstream (Lambda/API Gateway limitan a ~6 MB).
pub const PROXY_MAX_BODY_HARD_CAP: usize = 5 * 1024 * 1024;

/// Reintentos de `EnsureFreshSession` mientras otra invocacion refresca.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshRetry {
    pub max_attempts: u32,
    pub base: Duration,
    pub cap: Duration,
}

impl Default for RefreshRetry {
    fn default() -> Self {
        Self {
            max_attempts: 8,
            base: Duration::from_millis(50),
            cap: Duration::from_secs(1),
        }
    }
}

impl RefreshRetry {
    /// `base * 2^attempt`, acotado por `cap`.
    pub fn delay(&self, attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.cap)
    }
}

/// Configuracion de la capa de aplicacion. La construye el composition root a partir de
/// las variables de entorno (§8).
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// `https://app.example.com`, sin barra final.
    pub public_origin: String,
    pub session: SessionPolicy,
    pub pending: PendingPolicy,
    pub ws_ticket: WsTicketPolicy,
    pub refresh_retry: RefreshRetry,
    /// Ya acotado por `PROXY_MAX_BODY_HARD_CAP`.
    pub proxy_max_body: usize,
    /// Nombre (en minusculas) de la cabecera CSRF obligatoria.
    pub csrf_header: String,
}

impl AppConfig {
    /// Aplica el tope duro al limite de body.
    #[must_use]
    pub fn with_proxy_max_body(mut self, bytes: usize) -> Self {
        self.proxy_max_body = bytes.min(PROXY_MAX_BODY_HARD_CAP);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_exponencial_con_tope() {
        let r = RefreshRetry::default();
        assert_eq!(r.delay(0), Duration::from_millis(50));
        assert_eq!(r.delay(3), Duration::from_millis(400));
        assert_eq!(r.delay(5), Duration::from_secs(1));
        assert_eq!(r.delay(40), Duration::from_secs(1));
    }
}
