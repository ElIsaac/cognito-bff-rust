use std::time::Duration;

use crate::ids::random_id;
use crate::{DomainError, IdHash, Timestamp, UserInfo};

random_id!(
    /// Boleto de un solo uso para abrir un WebSocket: el navegador no tiene tokens, asi que
    /// pide este valor al BFF (con su cookie) y lo presenta en el handshake.
    WsTicketId
);

/// Lo que se guarda por boleto. El servicio de WebSocket lo consume (lectura + borrado
/// atomico) en `$connect`.
#[derive(Debug, Clone)]
pub struct WsTicket {
    pub id_hash: IdHash,
    /// Sesion que lo emitio: permite cerrar sus conexiones al hacer logout.
    pub session_hash: IdHash,
    pub user: UserInfo,
    pub created_at: Timestamp,
}

const WS_TICKET_MAX_TTL: Duration = Duration::from_mins(2);

/// Vida de un boleto (`WS_TICKET_TTL_SECS`, 30 s por defecto).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsTicketPolicy {
    ttl: Duration,
}

impl Default for WsTicketPolicy {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(30),
        }
    }
}

impl WsTicketPolicy {
    /// # Errors
    /// `DomainError::InvalidPolicy` si `ttl` es cero o mayor que dos minutos.
    pub fn new(ttl: Duration) -> Result<Self, DomainError> {
        if ttl.is_zero() || ttl > WS_TICKET_MAX_TTL {
            return Err(DomainError::InvalidPolicy("ttl de boleto ws fuera de (0, 120] s"));
        }
        Ok(Self { ttl })
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn expires_at(&self, created_at: Timestamp) -> Timestamp {
        created_at.saturating_add(self.ttl)
    }

    pub fn is_expired(&self, t: &WsTicket, now: Timestamp) -> bool {
        now >= self.expires_at(t.created_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RANDOM_ID_BYTES, SessionId, Subject};

    #[test]
    fn expira_y_redacta() {
        let id = WsTicketId::from_bytes([5; RANDOM_ID_BYTES]);
        assert_eq!(format!("{id:?}"), "WsTicketId([REDACTED])");
        let t = WsTicket {
            id_hash: id.hash(),
            session_hash: SessionId::from_bytes([6; RANDOM_ID_BYTES]).hash(),
            user: UserInfo::new(Subject::new("s".into()).unwrap(), None, None, vec![]),
            created_at: Timestamp::from_secs(100),
        };
        let p = WsTicketPolicy::default();
        assert!(!p.is_expired(&t, Timestamp::from_secs(129)));
        assert!(p.is_expired(&t, Timestamp::from_secs(130)));
        assert!(WsTicketPolicy::new(Duration::from_secs(121)).is_err());
    }
}
