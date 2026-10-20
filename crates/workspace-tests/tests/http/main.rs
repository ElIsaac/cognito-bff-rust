//! Suite de seguridad HTTP del BFF: el `Router` real de `http-axum` sobre `App<MemPorts>`,
//! conducido en proceso con `tower::ServiceExt::oneshot` (sin sockets). Cada test documenta
//! el ataque que cubre.

// Los doc comments son prosa en espanol (IdP, CSRF, ...), no APIs; los tests largos son
// tablas de casos de ataque.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

mod account;
mod callback;
mod cookies;
mod csrf;
mod errores;
mod fugas;
mod login;
mod me;
mod origin_verify;
mod proxy;
mod support;
mod ws_ticket;
