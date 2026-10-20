//! Casos de uso del BFF sobre puertos abstractos.
//!
//! `App<P>` agrupa los casos de uso; cada metodo es un caso de uso del plan (§4.4). La capa
//! HTTP solo traduce peticiones a estas llamadas y resultados a respuestas.

mod config;
pub mod csrf;
mod error;
pub mod headers;
pub mod ports;
mod usecases;

use std::sync::Arc;

pub use config::{AppConfig, PROXY_MAX_BODY_HARD_CAP, RefreshRetry};
pub use error::{AppError, LoginError};
pub use usecases::login::{CallbackParams, CompletedLogin, StartLoginOutcome};
pub use usecases::proxy::ProxyCall;
pub use usecases::ws_ticket::IssuedWsTicket;

use ports::Ports;

/// Punto de entrada de la capa de aplicacion. Barato de clonar.
#[derive(Debug)]
pub struct App<P: Ports> {
    ports: Arc<P>,
    cfg: AppConfig,
}

impl<P: Ports> Clone for App<P> {
    fn clone(&self) -> Self {
        Self {
            ports: Arc::clone(&self.ports),
            cfg: self.cfg.clone(),
        }
    }
}

impl<P: Ports> App<P> {
    pub fn new(ports: Arc<P>, cfg: AppConfig) -> Self {
        Self { ports, cfg }
    }

    pub fn config(&self) -> &AppConfig {
        &self.cfg
    }

    pub fn ports(&self) -> &P {
        &self.ports
    }
}
