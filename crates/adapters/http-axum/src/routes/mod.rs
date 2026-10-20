pub(crate) mod account;
pub(crate) mod auth;
pub(crate) mod proxy;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// `303 See Other` a `location`. Las ubicaciones posibles (URL de Cognito, `ReturnTo`,
/// ruta de error) ya son ASCII visible; si no, se va a `/`.
pub(crate) fn see_other(location: &str) -> Response {
    let value = HeaderValue::from_str(location).unwrap_or_else(|_| HeaderValue::from_static("/"));
    (StatusCode::SEE_OTHER, [(header::LOCATION, value)]).into_response()
}

/// JSON sin cache.
pub(crate) fn json(status: StatusCode, body: &serde_json::Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("application/json")),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        body.to_string(),
    )
        .into_response()
}
