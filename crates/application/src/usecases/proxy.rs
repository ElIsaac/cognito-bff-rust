//! `ProxyRequest` (§6.5). CSRF lo valida la capa HTTP antes de llamar aqui.

use std::time::Duration;

use domain::ProxyPath;

use crate::headers::{request_allowlist, response_filter};
use crate::ports::{
    Clock, Header, Method, Ports, UpstreamApi, UpstreamError, UpstreamRequest, UpstreamResponse,
};
use crate::{App, AppError};

/// Peticion del navegador a `/api/*`, ya separada por la capa HTTP.
pub struct ProxyCall<'a> {
    pub session_cookie: Option<&'a str>,
    pub method: Method,
    /// Lo que sigue a `/api/`, sin decodificar.
    pub path: &'a str,
    pub query: Option<&'a str>,
    /// Nombres en minusculas.
    pub headers: &'a [Header],
    pub body: Vec<u8>,
    /// `Clock::monotonic` al empezar la peticion: de aqui se descuenta el presupuesto.
    pub started: Duration,
}

impl std::fmt::Debug for ProxyCall<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCall")
            .field("session_cookie", &self.session_cookie.map(|_| "[REDACTED]"))
            .field("method", &self.method)
            .field("path", &self.path)
            .field(
                "headers",
                &self.headers.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            )
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl<P: Ports> App<P> {
    /// # Errors
    /// `BadRequest` (ruta), `PayloadTooLarge`, `Unauthorized`, `UpstreamTimeout`,
    /// `UpstreamUnavailable` y los de `ensure_fresh_session`.
    pub async fn proxy(&self, call: ProxyCall<'_>) -> Result<UpstreamResponse, AppError> {
        let path = ProxyPath::parse(call.path).map_err(|_| AppError::BadRequest)?;
        if call.body.len() > self.cfg.proxy_max_body {
            return Err(AppError::PayloadTooLarge);
        }
        let session = self.ensure_fresh_session(call.session_cookie).await?;
        // Lo que queda del presupuesto tras el refresh: si ya no hay, ni se llama al upstream.
        let spent = self.ports.clock().monotonic().saturating_sub(call.started);
        let remaining = self
            .cfg
            .request_budget
            .checked_sub(spent)
            .filter(|r| !r.is_zero())
            .ok_or(AppError::UpstreamTimeout)?;

        let req = UpstreamRequest {
            method: call.method,
            path,
            query: call.query.filter(|q| !q.is_empty()).map(str::to_owned),
            headers: request_allowlist(call.headers),
            body: call.body,
            bearer: session.tokens.access,
            timeout: Some(remaining),
        };
        let mut resp = self.ports.upstream().forward(req).await.map_err(|e| {
            tracing::warn!(error = %e, "upstream fallo");
            match e {
                UpstreamError::Timeout => AppError::UpstreamTimeout,
                UpstreamError::TooLarge | UpstreamError::Unavailable => AppError::UpstreamUnavailable,
            }
        })?;
        resp.headers = response_filter(&resp.headers);
        Ok(resp)
    }
}
