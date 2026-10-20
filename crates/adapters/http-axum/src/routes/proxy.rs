//! `ANY /api/*` (§6.5).

use application::ports::{Clock, Ports, SecretProvider};
use application::{AppError, ProxyCall};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;

use crate::middleware::{RequestStart, header_pairs, method_of};
use crate::{ApiError, St, cookies};

pub(crate) async fn forward<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    req: Request,
) -> Result<Response, ApiError> {
    let method = method_of(req.method()).ok_or(ApiError::MethodNotAllowed)?;
    let (parts, body) = req.into_parts();
    // La ruta sin decodificar: `ProxyPath` decide que se acepta.
    let path = parts.uri.path().strip_prefix("/api/").ok_or(ApiError::NotFound)?;
    let max = st.app.config().proxy_max_body;
    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > max as u64) {
        return Err(AppError::PayloadTooLarge.into());
    }
    let body = axum::body::to_bytes(body, max)
        .await
        .map_err(|_| AppError::PayloadTooLarge)?;
    let headers = header_pairs(&parts.headers);
    let cookie = cookies::read(&parts.headers, &st.cfg.session_cookie);
    let started = parts
        .extensions
        .get::<RequestStart>()
        .map_or_else(|| st.app.ports().clock().monotonic(), |s| s.0);

    let up = st
        .app
        .proxy(ProxyCall {
            session_cookie: cookie.as_deref(),
            method,
            path,
            query: parts.uri.query(),
            headers: &headers,
            body: body.to_vec(),
            started,
        })
        .await?;

    let status = StatusCode::from_u16(up.status).map_err(|_| AppError::UpstreamUnavailable)?;
    let mut resp = Response::new(Body::from(up.body));
    *resp.status_mut() = status;
    // Ya filtradas por `response_filter` (sin `Set-Cookie`, hop-by-hop ni cache); el
    // `no-store` lo fija el middleware de contexto.
    for (k, v) in up.headers {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
            resp.headers_mut().append(name, value);
        }
    }
    Ok(resp)
}
