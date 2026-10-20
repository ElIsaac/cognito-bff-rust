//! Entrada HTTP del BFF (§6, §7, decision 49).
//!
//! Solo traduce: lee cookies, cabeceras y cuerpo, llama a un caso de uso de `App` y arma
//! la respuesta. CSRF, `X-Origin-Verify` y el formato de los errores son middlewares que
//! aplican a todas las rutas.

mod cookies;
mod errors;
mod middleware;
mod routes;

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;

use std::sync::Arc;

use application::App;
use application::ports::{Ports, SecretProvider};
use axum::Router;
use axum::routing::{any, get, post};

pub use cookies::PENDING_COOKIE;
pub use errors::ApiError;

/// Lo que la capa HTTP necesita ademas de `AppConfig`.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Nombre de la cookie de sesion; debe empezar por `__Host-`.
    pub session_cookie: String,
    /// Ruta a la que vuelve un login fallido, sin query (se le agrega `?code=`).
    pub auth_error_path: String,
    /// Nombre o ARN del secreto de `X-Origin-Verify`; `None` lo desactiva.
    pub origin_verify_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpConfigError {
    #[error("COOKIE_NAME debe empezar por __Host- y ser un token valido")]
    CookieName,
    #[error("AUTH_ERROR_REDIRECT_PATH debe ser una ruta local sin query")]
    ErrorPath,
}

impl HttpConfig {
    /// # Errors
    /// `HttpConfigError` con la primera regla incumplida.
    pub fn validate(&self) -> Result<(), HttpConfigError> {
        if !cookies::valid_name(&self.session_cookie) || self.session_cookie == PENDING_COOKIE {
            return Err(HttpConfigError::CookieName);
        }
        let ok_path = domain::ReturnTo::parse(&self.auth_error_path).is_ok()
            && !self.auth_error_path.contains(['?', '#']);
        if !ok_path {
            return Err(HttpConfigError::ErrorPath);
        }
        Ok(())
    }
}

pub(crate) struct Shared<P: Ports, S> {
    pub app: App<P>,
    pub cfg: HttpConfig,
    pub secrets: Arc<S>,
}

pub(crate) type St<P, S> = Arc<Shared<P, S>>;

/// Router completo del BFF. `secrets` solo se usa para `X-Origin-Verify`.
///
/// # Errors
/// `HttpConfigError` si la configuracion HTTP no es valida.
pub fn router<P, S>(app: App<P>, cfg: HttpConfig, secrets: Arc<S>) -> Result<Router, HttpConfigError>
where
    P: Ports,
    S: SecretProvider + 'static,
{
    cfg.validate()?;
    let state: St<P, S> = Arc::new(Shared { app, cfg, secrets });
    let routes = Router::new()
        .route("/auth/login", get(routes::auth::login::<P, S>))
        .route("/auth/callback", get(routes::auth::callback::<P, S>))
        .route("/auth/me", get(routes::auth::me::<P, S>))
        .route("/auth/logout", post(routes::auth::logout::<P, S>))
        .route("/auth/ws-ticket", post(routes::auth::ws_ticket::<P, S>))
        .route("/auth/account/mfa", get(routes::account::mfa_status::<P, S>))
        .route(
            "/auth/account/mfa/totp/associate",
            post(routes::account::associate::<P, S>),
        )
        .route(
            "/auth/account/mfa/totp/verify",
            post(routes::account::verify::<P, S>),
        )
        .route(
            "/auth/account/mfa/preference",
            post(routes::account::preference::<P, S>),
        )
        .route(
            "/auth/account/change-password",
            post(routes::account::change_password::<P, S>),
        )
        .route("/api/{*rest}", any(routes::proxy::forward::<P, S>))
        .fallback(|| async { ApiError::NotFound })
        .method_not_allowed_fallback(|| async { ApiError::MethodNotAllowed });
    Ok(routes
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::csrf::<P, S>,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::origin_verify::<P, S>,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::context::<P, S>,
        ))
        .with_state(state))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HttpConfig {
        HttpConfig {
            session_cookie: "__Host-bff_session".into(),
            auth_error_path: "/".into(),
            origin_verify_secret: None,
        }
    }

    #[test]
    fn valida_config() {
        assert_eq!(cfg().validate(), Ok(()));
        let c = |f: fn(&mut HttpConfig)| {
            let mut c = cfg();
            f(&mut c);
            c.validate()
        };
        assert_eq!(
            c(|c| c.session_cookie = "bff_session".into()),
            Err(HttpConfigError::CookieName)
        );
        assert_eq!(
            c(|c| c.session_cookie = PENDING_COOKIE.into()),
            Err(HttpConfigError::CookieName)
        );
        assert_eq!(
            c(|c| c.auth_error_path = "//evil.com".into()),
            Err(HttpConfigError::ErrorPath)
        );
        assert_eq!(
            c(|c| c.auth_error_path = "/login?x=1".into()),
            Err(HttpConfigError::ErrorPath)
        );
        assert_eq!(c(|c| c.auth_error_path = "/login".into()), Ok(()));
    }
}
