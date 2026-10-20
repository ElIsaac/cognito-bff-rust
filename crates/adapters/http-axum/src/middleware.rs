//! Middlewares comunes a todas las rutas (decision 49). Orden, de afuera hacia adentro:
//! `context` → `origin_verify` → `csrf` → handler.

use std::fmt::Write as _;
use std::time::Instant;

use application::AppError;
use application::csrf;
use application::ports::{Header, Method, Ports, RandomGenerator, SecretProvider};
use axum::body::Body;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;
use tracing::Instrument;

use crate::errors::{ApiError, ErrorCode};
use crate::{St, cookies};

pub(crate) const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
const ORIGIN_VERIFY: HeaderName = HeaderName::from_static("x-origin-verify");
const REQUEST_ID_MAX: usize = 64;

/// Cabeceras como pares `(nombre en minusculas, valor)` para reenviar al upstream; se
/// omiten los valores que no son texto visible.
pub(crate) fn header_pairs(h: &HeaderMap) -> Vec<Header> {
    h.iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_owned(), v.to_owned())))
        .collect()
}

/// Igual, pero sin omitir nada: un valor ilegible queda con caracteres de reemplazo, que
/// nunca coinciden con un valor aceptado y si cuentan como presencia o repeticion. Para
/// las comprobaciones de seguridad, que deben fallar cerrado.
fn header_pairs_lossy(h: &HeaderMap) -> Vec<Header> {
    h.iter()
        .map(|(k, v)| {
            (
                k.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

pub(crate) fn method_of(m: &axum::http::Method) -> Option<Method> {
    use axum::http::Method as M;
    Some(match *m {
        M::GET => Method::Get,
        M::HEAD => Method::Head,
        M::POST => Method::Post,
        M::PUT => Method::Put,
        M::PATCH => Method::Patch,
        M::DELETE => Method::Delete,
        M::OPTIONS => Method::Options,
        _ => return None,
    })
}

fn incoming_request_id(h: &HeaderMap) -> Option<String> {
    let mut all = h.get_all(REQUEST_ID).iter();
    let v = all.next()?.to_str().ok()?;
    let ok = all.next().is_none()
        && !v.is_empty()
        && v.len() <= REQUEST_ID_MAX
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'='));
    ok.then(|| v.to_owned())
}

fn new_request_id(rng: &impl RandomGenerator) -> String {
    rng.bytes32()[..16]
        .iter()
        .fold(String::with_capacity(32), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// `X-Request-ID`, span de la peticion, log de acceso y cuerpo de los errores.
pub(crate) async fn context<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    mut req: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let id = incoming_request_id(req.headers()).unwrap_or_else(|| new_request_id(st.app.ports().rng()));
    let id_value = HeaderValue::from_str(&id).unwrap_or_else(|_| HeaderValue::from_static("invalid"));
    // El upstream recibe el mismo id (la lista blanca del proxy deja pasar `x-request-id`).
    req.headers_mut().insert(REQUEST_ID, id_value.clone());
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "-".to_owned(), |m| m.as_str().to_owned());
    let is_auth = route.starts_with("/auth/");
    let span = tracing::info_span!("request", request_id = %id, method = %req.method(), route = %route);

    let mut resp = next.run(req).instrument(span.clone()).await;

    if let Some(ErrorCode(code)) = resp.extensions().get::<ErrorCode>().copied() {
        let body = serde_json::json!({ "error": code, "requestId": id }).to_string();
        let h = resp.headers_mut();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        h.remove(header::CONTENT_LENGTH);
        if code == AppError::Unauthorized.code() {
            h.append(header::SET_COOKIE, cookies::clear(&st.cfg.session_cookie));
        }
        *resp.body_mut() = Body::from(body);
    }
    if is_auth && !resp.headers().contains_key(header::CACHE_CONTROL) {
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp.headers_mut().insert(REQUEST_ID, id_value);

    let status = resp.status().as_u16();
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    span.in_scope(|| {
        if status >= 500 {
            tracing::warn!(status, latency_ms, "peticion");
        } else {
            tracing::info!(status, latency_ms, "peticion");
        }
    });
    resp
}

/// §7.3: con el secreto configurado, toda peticion trae `X-Origin-Verify` igual al valor
/// actual o al anterior (rotacion). Falla cerrado si Secrets Manager no responde.
pub(crate) async fn origin_verify<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    mut req: Request,
    next: Next,
) -> Response {
    if let Some(name) = &st.cfg.origin_verify_secret {
        let mut values = req.headers().get_all(ORIGIN_VERIFY).iter();
        let got = match (values.next(), values.next()) {
            (Some(v), None) => v.as_bytes().to_vec(),
            _ => return ApiError::App(AppError::Forbidden).into_response(),
        };
        let secret = match st.secrets.get(name).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "no se pudo leer el secreto de origen");
                return ApiError::App(AppError::Internal).into_response();
            }
        };
        let current = got.ct_eq(secret.current.expose_secret().as_bytes());
        let previous = secret.previous.as_ref().map_or(subtle::Choice::from(0), |p| {
            got.ct_eq(p.expose_secret().as_bytes())
        });
        if !bool::from(current | previous) {
            tracing::warn!("X-Origin-Verify ausente o incorrecto");
            return ApiError::App(AppError::Forbidden).into_response();
        }
    }
    req.headers_mut().remove(ORIGIN_VERIFY);
    next.run(req).await
}

/// §7.2 para todo metodo que cambia estado, en `/auth/*` y `/api/*`.
pub(crate) async fn csrf<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(method) = method_of(req.method()) else {
        return ApiError::MethodNotAllowed.into_response();
    };
    if method.is_unsafe() {
        let cfg = st.app.config();
        let headers = header_pairs_lossy(req.headers());
        if !csrf::check(method, &headers, &cfg.public_origin, &cfg.csrf_header) {
            tracing::warn!("CSRF rechazado");
            return ApiError::App(AppError::Csrf).into_response();
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_entrante() {
        let mut h = HeaderMap::new();
        assert_eq!(incoming_request_id(&h), None);
        h.insert(REQUEST_ID, HeaderValue::from_static("abc-123_x.y"));
        assert_eq!(incoming_request_id(&h).as_deref(), Some("abc-123_x.y"));
        // Formato del requestId de API Gateway.
        h.insert(REQUEST_ID, HeaderValue::from_static("JkHMWh3GiYcEMvA="));
        assert_eq!(incoming_request_id(&h).as_deref(), Some("JkHMWh3GiYcEMvA="));
        h.insert(REQUEST_ID, HeaderValue::from_static("a b"));
        assert_eq!(incoming_request_id(&h), None);
        h.insert(REQUEST_ID, HeaderValue::from_str(&"a".repeat(65)).unwrap());
        assert_eq!(incoming_request_id(&h), None);
        h.insert(REQUEST_ID, HeaderValue::from_static("a"));
        h.append(REQUEST_ID, HeaderValue::from_static("b"));
        assert_eq!(incoming_request_id(&h), None);
    }
}
