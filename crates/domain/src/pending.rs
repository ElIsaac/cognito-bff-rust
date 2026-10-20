use std::time::Duration;

use crate::{CodeVerifier, DomainError, IdHash, Nonce, ReturnTo, State, Timestamp};

/// Login en curso: lo que se guarda entre `/auth/login` y `/auth/callback`. Se consume una
/// sola vez.
#[derive(Debug, Clone)]
pub struct PendingAuth {
    pub id_hash: IdHash,
    pub state: State,
    pub nonce: Nonce,
    pub code_verifier: CodeVerifier,
    pub return_to: ReturnTo,
    pub created_at: Timestamp,
}

const PENDING_MAX_TTL: Duration = Duration::from_secs(3600);

/// Vida de un login en curso (`PENDING_TTL_SECS`, 600 s por defecto).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingPolicy {
    ttl: Duration,
}

impl Default for PendingPolicy {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(600),
        }
    }
}

impl PendingPolicy {
    /// # Errors
    /// `DomainError::InvalidPolicy` si `ttl` es cero o mayor que una hora.
    pub fn new(ttl: Duration) -> Result<Self, DomainError> {
        if ttl.is_zero() || ttl > PENDING_MAX_TTL {
            return Err(DomainError::InvalidPolicy("ttl de pending fuera de (0, 3600] s"));
        }
        Ok(Self { ttl })
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn expires_at(&self, created_at: Timestamp) -> Timestamp {
        created_at.saturating_add(self.ttl)
    }

    pub fn is_expired(&self, p: &PendingAuth, now: Timestamp) -> bool {
        now >= self.expires_at(p.created_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PendingId, RANDOM_ID_BYTES};

    fn pending(created: u64) -> PendingAuth {
        PendingAuth {
            id_hash: PendingId::from_bytes([1; RANDOM_ID_BYTES]).hash(),
            state: State::from_bytes([2; RANDOM_ID_BYTES]),
            nonce: Nonce::from_bytes([3; RANDOM_ID_BYTES]),
            code_verifier: CodeVerifier::from_bytes([4; RANDOM_ID_BYTES]),
            return_to: ReturnTo::default(),
            created_at: Timestamp::from_secs(created),
        }
    }

    #[test]
    fn expira_a_los_diez_minutos() {
        let p = PendingPolicy::default();
        let a = pending(100);
        assert!(!p.is_expired(&a, Timestamp::from_secs(699)));
        assert!(p.is_expired(&a, Timestamp::from_secs(700)));
    }

    #[test]
    fn debug_no_filtra_secretos() {
        let a = pending(100);
        let dbg = format!("{a:?}");
        for s in [
            a.state.expose_secret(),
            a.nonce.expose_secret(),
            a.code_verifier.expose_secret().to_owned(),
        ] {
            assert!(!dbg.contains(&s), "{dbg}");
        }
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn ttl_invalido() {
        assert!(PendingPolicy::new(Duration::ZERO).is_err());
        assert!(PendingPolicy::new(Duration::from_secs(3601)).is_err());
    }
}
