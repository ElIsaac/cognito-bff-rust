#![allow(clippy::unused_async_trait_impl)]

use std::sync::Arc;

use domain::{IdHash, Timestamp};
use in_memory::{MemPending, MemSessions, MemTickets};

#[derive(Debug)]
pub struct Harness {
    sessions: Arc<MemSessions>,
    pending: Arc<MemPending>,
    tickets: Arc<MemTickets>,
}

impl Harness {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(MemSessions::new()),
            pending: Arc::new(MemPending::new()),
            tickets: Arc::new(MemTickets::new()),
        }
    }
}

impl crate::suite::Harness for Harness {
    type Sessions = MemSessions;
    type Pending = MemPending;
    type Tickets = MemTickets;

    fn sessions(&self) -> Arc<MemSessions> {
        Arc::clone(&self.sessions)
    }

    fn pending(&self) -> Arc<MemPending> {
        Arc::clone(&self.pending)
    }

    fn tickets(&self) -> Arc<MemTickets> {
        Arc::clone(&self.tickets)
    }

    async fn session_ttl(&self, id: &IdHash) -> Option<Timestamp> {
        self.sessions.ttl_of(id)
    }

    async fn session_has_lock_attr(&self, id: &IdHash) -> bool {
        self.sessions
            .snapshot(id)
            .is_some_and(|s| s.refresh_lock_until.is_some())
    }

    async fn pending_ttl(&self, id: &IdHash) -> Option<Timestamp> {
        self.pending.ttl_of(id)
    }

    async fn ticket_ttl(&self, id: &IdHash) -> Option<Timestamp> {
        self.tickets.ttl_of(id)
    }
}
