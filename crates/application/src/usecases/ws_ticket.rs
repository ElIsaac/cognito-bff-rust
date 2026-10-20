//! `IssueWsTicket` (decision 27, §18).

use std::time::Duration;

use domain::{WsTicket, WsTicketId};

use crate::ports::{Clock, Ports, RandomGenerator, WsTicketStore};
use crate::usecases::session::internal;
use crate::{App, AppError};

#[derive(Debug)]
pub struct IssuedWsTicket {
    pub ticket: WsTicketId,
    pub expires_in: Duration,
}

impl<P: Ports> App<P> {
    /// `POST /auth/ws-ticket` (CSRF lo valida la capa HTTP).
    ///
    /// # Errors
    /// Los de `ensure_fresh_session` e `Internal` si no se pudo guardar.
    pub async fn issue_ws_ticket(&self, cookie: Option<&str>) -> Result<IssuedWsTicket, AppError> {
        let session = self.ensure_fresh_session(cookie).await?;
        let id = WsTicketId::from_bytes(self.ports.rng().bytes32());
        let ticket = WsTicket {
            id_hash: id.hash(),
            session_hash: session.id_hash,
            user: session.user,
            created_at: self.ports.clock().now(),
        };
        let ttl = self.cfg.ws_ticket.expires_at(ticket.created_at);
        self.ports.tickets().put(&ticket, ttl).await.map_err(internal)?;
        Ok(IssuedWsTicket {
            ticket: id,
            expires_in: self.cfg.ws_ticket.ttl(),
        })
    }
}
