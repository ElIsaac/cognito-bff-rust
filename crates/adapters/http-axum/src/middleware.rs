//! Middlewares comunes a todas las rutas (decision 49). Orden, de afuera hacia adentro:
//! `context` → `origin_verify` → `csrf` → handler.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use application::AppError;
use application::csrf;
use application::ports::{Clock, Header, Method, Ports, RandomGenerator, SecretProvider};
use axum::body::Body;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tracing::Instrument;

use crate::St;
use crate::cookies::{self, Lookup};
use crate::errors::{ApiError, ErrorCode};

pub(crate) const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
const ORIGIN_VERIFY: HeaderName = HeaderName::from_static("x-origin-verify");
const REQUEST_ID_MAX: usize = 64;
const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");

/// `Clock::monotonic` al entrar la peticion; el proxy descuenta de aqui su presupuesto.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RequestStart(pub Duration);

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

/// `trace-id` de un `traceparent` valido (W3C): `vv-<32 hex>-<16 hex>-<2 hex>`, en minusculas,
/// sin ceros enteros y con una sola cabecera. Cualquier otra cosa se ignora.
fn trace_id_of(h: &HeaderMap) -> Option<&str> {
    let mut all = h.get_all(TRACEPARENT).iter();
    let raw = all.next()?.to_str().ok()?;
    if all.next().is_some() {
        return None;
    }
    let mut parts = raw.split('-');
    let (version, trace, parent, flags) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let hex =
        |s: &str, len: usize| s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let not_zero = |s: &str| s.bytes().any(|b| b != b'0');
    // La version 00 no admite campos de mas; las futuras si, al final.
    let version_ok = hex(version, 2) && version != "ff" && (version != "00" || parts.next().is_none());
    (version_ok && hex(trace, 32) && not_zero(trace) && hex(parent, 16) && not_zero(parent) && hex(flags, 2))
        .then_some(trace)
}

fn new_request_id(rng: &impl RandomGenerator) -> String {
    rng.bytes32()[..16]
        .iter()
        .fold(String::with_capacity(32), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Cabeceras de seguridad propias, aunque no haya `CloudFront` delante (auditoria ZAP): HSTS,
/// `nosniff` y `Cross-Origin-Resource-Policy` en todo; en `/auth/*`, que nunca sirve HTML,
/// una CSP que no deja cargar ni enmarcar nada (si la respuesta no trae otra).
fn security_headers(h: &mut HeaderMap, is_auth: bool) {
    h.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    if is_auth && !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        );
    }
}

/// `X-Request-ID`, span de la peticion, log de acceso y cuerpo de los errores.
pub(crate) async fn context<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    mut req: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    req.extensions_mut()
        .insert(RequestStart(st.app.ports().clock().monotonic()));
    let id = incoming_request_id(req.headers()).unwrap_or_else(|| new_request_id(st.app.ports().rng()));
    let id_value = HeaderValue::from_str(&id).unwrap_or_else(|_| HeaderValue::from_static("invalid"));
    // El upstream recibe el mismo id (la lista blanca del proxy deja pasar `x-request-id`).
    req.headers_mut().insert(REQUEST_ID, id_value.clone());
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "-".to_owned(), |m| m.as_str().to_owned());
    let is_auth = route.starts_with("/auth/");
    let path = req.uri().path();
    let is_api = path == "/api" || path.starts_with("/api/");
    // Una cabecera ilegible o enorme no dice nada de la sesion: no se manda borrarla.
    let clear_session = cookies::lookup(req.headers(), &st.cfg.session_cookie) != Lookup::Unreadable;
    let span = tracing::info_span!(
        "request",
        request_id = %id,
        method = %req.method(),
        route = %route,
        trace_id = trace_id_of(req.headers()),
        sub_hash = tracing::field::Empty,
    );

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
        if code == AppError::Unauthorized.code() && clear_session {
            h.append(header::SET_COOKIE, cookies::clear(&st.cfg.session_cookie));
        }
        *resp.body_mut() = Body::from(body);
    }
    // Dec. 8: nada de `/api/*` se cachea, diga lo que diga el upstream.
    if is_api || (is_auth && !resp.headers().contains_key(header::CACHE_CONTROL)) {
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    security_headers(resp.headers_mut(), is_auth);
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
        let verdict = st
            .origin
            .verify(&*st.secrets, st.app.ports().clock(), name, &got)
            .await;
        match verdict {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!("X-Origin-Verify ausente o incorrecto");
                return ApiError::App(AppError::Forbidden).into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, "no se pudo leer el secreto de origen");
                return ApiError::App(AppError::Internal).into_response();
            }
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
    fn trace_id_de_traceparent() {
        const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
        let con = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(TRACEPARENT, HeaderValue::from_str(v).unwrap());
            h
        };
        assert_eq!(trace_id_of(&HeaderMap::new()), None);
        let ok = format!("00-{TRACE}-00f067aa0ba902b7-01");
        assert_eq!(trace_id_of(&con(&ok)), Some(TRACE));
        // Version futura: se admiten campos de mas.
        assert_eq!(
            trace_id_of(&con(&format!("01-{TRACE}-00f067aa0ba902b7-01-extra"))),
            Some(TRACE)
        );
        for malo in [
            format!("00-{TRACE}-00f067aa0ba902b7-01-extra"),
            format!("ff-{TRACE}-00f067aa0ba902b7-01"),
            format!("00-{}-00f067aa0ba902b7-01", "0".repeat(32)),
            format!("00-{TRACE}-{}-01", "0".repeat(16)),
            format!("00-{}-00f067aa0ba902b7-01", TRACE.to_uppercase()),
            format!("00-{}-00f067aa0ba902b7-01", &TRACE[..31]),
            format!("00-{TRACE}-00f067aa0ba902b7"),
            format!("0-{TRACE}-00f067aa0ba902b7-01"),
            format!("00-{TRACE}-00f067aa0ba902b7-0g"),
            "basura".to_owned(),
        ] {
            assert_eq!(trace_id_of(&con(&malo)), None, "{malo}");
        }
        let mut dos = con(&ok);
        dos.append(TRACEPARENT, HeaderValue::from_str(&ok).unwrap());
        assert_eq!(trace_id_of(&dos), None);
    }

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
