/// Error de un caso de uso, ya sin detalles internos. La capa HTTP lo traduce a un status y
/// a `{"error": <code>, "requestId": ...}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AppError {
    #[error("unauthenticated")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("csrf")]
    Csrf,
    #[error("bad_request")]
    BadRequest,
    #[error("payload_too_large")]
    PayloadTooLarge,
    #[error("upstream_timeout")]
    UpstreamTimeout,
    #[error("upstream_unavailable")]
    UpstreamUnavailable,
    /// Otra invocacion sigue refrescando la sesion: `503` con `Retry-After: 1`.
    #[error("busy")]
    Busy,
    #[error("internal")]
    Internal,
}

impl AppError {
    /// Codigo estable para el cuerpo JSON.
    pub fn code(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::Csrf => "csrf",
            Self::BadRequest => "bad_request",
            Self::PayloadTooLarge => "payload_too_large",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::UpstreamUnavailable => "upstream_unavailable",
            Self::Busy => "busy",
            Self::Internal => "internal",
        }
    }
}

/// Fallo del callback de login. Termina en `303` a `AUTH_ERROR_REDIRECT_PATH?code=<code>`;
/// el codigo sale de esta lista blanca y nunca refleja `error_description`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LoginError {
    #[error("missing_pending")]
    MissingPending,
    #[error("invalid_state")]
    InvalidState,
    #[error("access_denied")]
    AccessDenied,
    #[error("invalid_request")]
    InvalidRequest,
    #[error("provider_error")]
    ProviderError,
    #[error("exchange_failed")]
    ExchangeFailed,
    #[error("provider_unavailable")]
    ProviderUnavailable,
    #[error("internal")]
    Internal,
}

impl LoginError {
    pub fn code(self) -> &'static str {
        match self {
            Self::MissingPending => "missing_pending",
            Self::InvalidState => "invalid_state",
            Self::AccessDenied => "access_denied",
            Self::InvalidRequest => "invalid_request",
            Self::ProviderError => "provider_error",
            Self::ExchangeFailed => "exchange_failed",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::Internal => "internal",
        }
    }

    /// Traduce el `error` del callback de Cognito a la lista blanca.
    pub fn from_provider(error: &str) -> Self {
        match error {
            "access_denied" => Self::AccessDenied,
            "invalid_request" => Self::InvalidRequest,
            _ => Self::ProviderError,
        }
    }
}
