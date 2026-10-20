//! Pruebas de integracion de `oidc-cognito` contra un Cognito simulado (servidor `axum` en
//! `127.0.0.1:0`) con llaves RSA generadas en cada ejecucion. Cada test documenta el ataque o
//! la regresion que cubre.

// Los doc comments son prosa en espanol (IdP, JWKS, ...), no APIs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

mod authorize;
mod canje;
mod fugas;
mod id_token;
mod jwks;
mod refresh;
mod support;
mod token_endpoint;
