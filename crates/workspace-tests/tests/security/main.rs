//! Suite de seguridad de la Fase 2 (plan 9.2) sobre `App<MemPorts>`: casos de uso reales,
//! fakes en memoria. Cada test documenta el ataque que cubre.

// Los doc comments son prosa en espanol (IdP, DynamoDB, ...), no APIs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

mod common;
mod csrf;
mod fugas;
mod oidc;
mod proxy;
mod refresh;
mod sesiones;
mod ws_ticket;
