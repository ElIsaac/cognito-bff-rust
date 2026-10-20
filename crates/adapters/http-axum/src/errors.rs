//! Errores HTTP. Los handlers devuelven `ApiError`; el middleware de contexto les pone el
//! cuerpo `{"error": <code>, "requestId": <id>}`, asi ningun error sale sin `requestId` ni
//! con detalles internos.

use application::{AccountRejection, AppError};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Marca en las extensiones de la respuesta: el middleware de contexto arma el cuerpo.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ErrorCode(pub &'static str);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    App(AppError),
    NotFound,
    MethodNotAllowed,
    UnsupportedMediaType,
}

impl From<AppError> for ApiError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

impl ApiError {
    pub fn status(self) -> StatusCode {
        match self {
            Self::App(e) => match e {
                AppError::Unauthorized => StatusCode::UNAUTHORIZED,
                AppError::Forbidden | AppError::Csrf => StatusCode::FORBIDDEN,
                AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
                AppError::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
                AppError::UpstreamUnavailable => StatusCode::BAD_GATEWAY,
                AppError::Busy => StatusCode::SERVICE_UNAVAILABLE,
                AppError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
                AppError::Account(AccountRejection::TooManyRequests) => StatusCode::TOO_MANY_REQUESTS,
                AppError::BadRequest | AppError::Account(_) => StatusCode::BAD_REQUEST,
            },
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::App(e) => e.code(),
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::UnsupportedMediaType => "unsupported_media_type",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = self.status().into_response();
        if self == Self::App(AppError::Busy) {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        resp.extensions_mut().insert(ErrorCode(self.code()));
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estados() {
        assert_eq!(ApiError::from(AppError::Csrf).status(), StatusCode::FORBIDDEN);
        assert_eq!(
            ApiError::from(AppError::Busy).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            ApiError::from(AppError::Account(AccountRejection::TooManyRequests)).status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            ApiError::from(AppError::Account(AccountRejection::CodeMismatch)).code(),
            "code_mismatch"
        );
        let r = ApiError::from(AppError::Busy).into_response();
        assert_eq!(r.headers()[header::RETRY_AFTER], "1");
    }
}
