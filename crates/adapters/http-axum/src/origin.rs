//! Estado de `X-Origin-Verify` (§7.3): rotacion con recarga acotada y ventana de gracia
//! del valor anterior.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use application::ports::{AdapterError, Clock, SecretProvider, SecretVersions};
use domain::Timestamp;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Intervalo minimo entre dos recargas forzadas del secreto.
pub(crate) const RELOAD_MIN_INTERVAL: Duration = Duration::from_secs(30);

type Fingerprint = [u8; 32];

#[derive(Debug, Default)]
struct State {
    /// Huella del valor actual visto por ultima vez y desde cuando se ve.
    current_seen: Option<(Fingerprint, Timestamp)>,
    last_reload: Option<Timestamp>,
}

#[derive(Debug)]
pub(crate) struct OriginVerify {
    previous_grace: Duration,
    state: Mutex<State>,
    /// Una sola recarga a la vez; las demas peticiones esperan y reutilizan su resultado.
    reload: tokio::sync::Mutex<()>,
}

impl OriginVerify {
    pub fn new(previous_grace: Duration) -> Self {
        Self {
            previous_grace,
            state: Mutex::new(State::default()),
            reload: tokio::sync::Mutex::new(()),
        }
    }

    /// `true` si `got` es el valor actual o, dentro de la gracia, el anterior. Ante un valor
    /// que no coincide se invalida y recarga el secreto antes de rechazar, como mucho una
    /// vez cada 30 s (una rotacion que aun no llego a la cache no deja a `CloudFront` fuera).
    ///
    /// # Errors
    /// El del proveedor si no se pudo leer el secreto (falla cerrado).
    pub async fn verify<S: SecretProvider, C: Clock>(
        &self,
        secrets: &S,
        clock: &C,
        name: &str,
        got: &[u8],
    ) -> Result<bool, AdapterError> {
        let versions = secrets.get(name).await?;
        if self.matches(&versions, got, clock.now()) {
            return Ok(true);
        }

        let _single_flight = self.reload.lock().await;
        let now = clock.now();
        if self.claim_reload(now) {
            tracing::info!("X-Origin-Verify no coincide: se recarga el secreto");
            secrets.invalidate(name);
        }
        match secrets.get(name).await {
            Ok(versions) => Ok(self.matches(&versions, got, clock.now())),
            Err(e) => {
                // El rechazo ya es seguro; la proxima lectura volvera a intentar la carga.
                tracing::warn!(error = %e, "no se pudo recargar el secreto de origen");
                Ok(false)
            }
        }
    }

    fn matches(&self, v: &SecretVersions, got: &[u8], now: Timestamp) -> bool {
        let observed = self.observe(v, now);
        let current = got.ct_eq(v.current.expose_secret().as_bytes());
        let in_grace = now.saturating_since(observed) < self.previous_grace;
        let previous = match &v.previous {
            Some(p) if in_grace => got.ct_eq(p.expose_secret().as_bytes()),
            _ => subtle::Choice::from(0),
        };
        bool::from(current | previous)
    }

    /// Desde cuando se ve el valor actual (ahora mismo si cambio).
    fn observe(&self, v: &SecretVersions, now: Timestamp) -> Timestamp {
        let fp: Fingerprint = Sha256::digest(v.current.expose_secret().as_bytes()).into();
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match s.current_seen {
            Some((seen, since)) if seen == fp => since,
            _ => {
                s.current_seen = Some((fp, now));
                now
            }
        }
    }

    /// `true` si toca recargar; deja anotado el intento aunque la recarga falle.
    fn claim_reload(&self, now: Timestamp) -> bool {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if s.last_reload
            .is_some_and(|t| now.saturating_since(t) < RELOAD_MIN_INTERVAL)
        {
            return false;
        }
        s.last_reload = Some(now);
        true
    }
}
