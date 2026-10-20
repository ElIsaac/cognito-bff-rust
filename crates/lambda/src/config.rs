//! Configuracion desde variables de entorno (§8). Los errores nombran la variable, nunca
//! su valor.

use std::time::Duration;

use application::{AppConfig, RefreshRetry};
use domain::{PendingPolicy, ReturnTo, SessionPolicy, SessionPolicyConfig, WsTicketPolicy};
use http_axum::HttpConfig;
use oidc_cognito::CognitoConfig;
use upstream_reqwest::UpstreamConfig;
use url::Url;

const DEFAULT_SCOPES: &str = "openid email profile";
const DEFAULT_COOKIE: &str = "__Host-bff_session";
const DEFAULT_CSRF_HEADER: &str = "X-Requested-With";
const DEFAULT_PROXY_MAX_BODY: u64 = 1024 * 1024;
const DEFAULT_PROXY_TIMEOUT_SECS: u64 = 10;
const DEFAULT_IDP_TIMEOUT_SECS: u64 = 4;
const DEFAULT_JWKS_TTL_SECS: u64 = 3600;
const DEFAULT_SECRET_TTL_SECS: u64 = 600;
const DEFAULT_PENDING_TTL_SECS: u64 = 600;
const DEFAULT_WS_TICKET_TTL_SECS: u64 = 30;
/// Intervalo minimo entre descargas del JWKS por `kid` desconocido (§7.6).
const JWKS_MIN_REFETCH: Duration = Duration::from_secs(60);
/// Tolerancia de reloj de `iat`/`exp` (§4.3).
const CLOCK_LEEWAY: Duration = Duration::from_secs(60);
const CALLBACK_PATH: &str = "/auth/callback";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("falta la variable {0}")]
    Missing(&'static str),
    #[error("valor invalido en {0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Cognito(#[from] oidc_cognito::ConfigError),
    #[error("{0}")]
    Http(#[from] http_axum::HttpConfigError),
}

/// Todo lo que el composition root necesita, ya validado.
#[derive(Debug, Clone)]
pub struct Config {
    pub app: AppConfig,
    pub cognito: CognitoConfig,
    pub http: HttpConfig,
    pub upstream: UpstreamConfig,
    pub table: String,
    // En local los secretos salen del entorno, sin cache.
    #[cfg_attr(feature = "local", allow(dead_code))]
    pub secret_cache_ttl: Duration,
    /// Solo con la feature `local` (`DynamoDB` Local).
    pub dynamodb_endpoint: Option<String>,
}

struct Env<'a>(&'a dyn Fn(&str) -> Option<String>);

impl Env<'_> {
    fn opt(&self, name: &'static str) -> Option<String> {
        (self.0)(name)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    }

    fn req(&self, name: &'static str) -> Result<String, ConfigError> {
        self.opt(name).ok_or(ConfigError::Missing(name))
    }

    fn or(&self, name: &'static str, default: &str) -> String {
        self.opt(name).unwrap_or_else(|| default.to_owned())
    }

    fn num(&self, name: &'static str, default: u64) -> Result<u64, ConfigError> {
        self.opt(name)
            .map_or(Ok(default), |v| v.parse().map_err(|_| ConfigError::Invalid(name)))
    }

    fn secs(&self, name: &'static str, default: u64) -> Result<Duration, ConfigError> {
        let n = self.num(name, default)?;
        if n == 0 {
            return Err(ConfigError::Invalid(name));
        }
        Ok(Duration::from_secs(n))
    }
}

/// `https://host[:puerto]` sin barra final ni nada mas; `http` solo para `localhost`.
fn public_origin(v: &str) -> Result<String, ConfigError> {
    const NAME: &str = "PUBLIC_ORIGIN";
    let url = Url::parse(v).map_err(|_| ConfigError::Invalid(NAME))?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1"));
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && local);
    let bare = url.path() == "/"
        && !v.ends_with('/')
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    if scheme_ok && bare && url.host_str().is_some() {
        Ok(v.to_owned())
    } else {
        Err(ConfigError::Invalid(NAME))
    }
}

fn local_path(env: &Env<'_>, name: &'static str) -> Result<String, ConfigError> {
    let v = env.or(name, "/");
    if ReturnTo::parse(&v).is_ok() && !v.contains(['?', '#']) {
        Ok(v)
    } else {
        Err(ConfigError::Invalid(name))
    }
}

impl Config {
    /// Lee y valida toda la configuracion.
    ///
    /// # Errors
    /// `ConfigError` con la primera variable que falta o no es valida.
    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let env = Env(lookup);
        let origin = public_origin(&env.req("PUBLIC_ORIGIN")?)?;

        let session = SessionPolicy::new(SessionPolicyConfig {
            absolute_ttl: env.secs("SESSION_ABSOLUTE_TTL_SECS", 30 * 24 * 3600)?,
            idle_ttl: env.secs("SESSION_IDLE_TTL_SECS", 12 * 3600)?,
            refresh_threshold: env.secs("ACCESS_REFRESH_THRESHOLD_SECS", 60)?,
            refresh_lease: env.secs("REFRESH_LEASE_SECS", 10)?,
            ..SessionPolicyConfig::default()
        })
        .map_err(|_| ConfigError::Invalid("SESSION_*"))?;
        let refresh_lease = env.secs("REFRESH_LEASE_SECS", 10)?;
        let pending = PendingPolicy::new(env.secs("PENDING_TTL_SECS", DEFAULT_PENDING_TTL_SECS)?)
            .map_err(|_| ConfigError::Invalid("PENDING_TTL_SECS"))?;
        let ws_ticket = WsTicketPolicy::new(env.secs("WS_TICKET_TTL_SECS", DEFAULT_WS_TICKET_TTL_SECS)?)
            .map_err(|_| ConfigError::Invalid("WS_TICKET_TTL_SECS"))?;
        let max_body = usize::try_from(env.num("PROXY_MAX_BODY_BYTES", DEFAULT_PROXY_MAX_BODY)?)
            .map_err(|_| ConfigError::Invalid("PROXY_MAX_BODY_BYTES"))?;
        let csrf_header = env
            .or("CSRF_HEADER_NAME", DEFAULT_CSRF_HEADER)
            .to_ascii_lowercase();
        let csrf_ok = !csrf_header.is_empty()
            && csrf_header
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !csrf_ok {
            return Err(ConfigError::Invalid("CSRF_HEADER_NAME"));
        }
        let app = AppConfig {
            public_origin: origin.clone(),
            session,
            pending,
            ws_ticket,
            refresh_retry: RefreshRetry::default(),
            proxy_max_body: 0,
            csrf_header,
        }
        .with_proxy_max_body(max_body);

        let exposed_claims = env
            .or("EXPOSED_CLAIMS", "")
            .split(',')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(str::to_owned)
            .collect();
        let cognito = CognitoConfig {
            issuer: env.req("COGNITO_ISSUER")?,
            domain: Url::parse(&env.req("COGNITO_DOMAIN")?)
                .map_err(|_| ConfigError::Invalid("COGNITO_DOMAIN"))?,
            client_id: env.req("COGNITO_CLIENT_ID")?,
            client_secret_name: env.req("COGNITO_CLIENT_SECRET_ARN")?,
            redirect_uri: format!("{origin}{CALLBACK_PATH}"),
            logout_uri: format!("{origin}{}", local_path(&env, "LOGOUT_REDIRECT_PATH")?),
            scopes: env.or("OIDC_SCOPES", DEFAULT_SCOPES),
            exposed_claims,
            http_timeout: env.secs("IDP_TIMEOUT_SECS", DEFAULT_IDP_TIMEOUT_SECS)?,
            jwks_cache_ttl: env.secs("JWKS_CACHE_TTL_SECS", DEFAULT_JWKS_TTL_SECS)?,
            jwks_min_refetch: JWKS_MIN_REFETCH,
            leeway: CLOCK_LEEWAY,
            require_https: true,
        };
        cognito.validate(refresh_lease)?;

        let http = HttpConfig {
            session_cookie: env.or("COOKIE_NAME", DEFAULT_COOKIE),
            auth_error_path: local_path(&env, "AUTH_ERROR_REDIRECT_PATH")?,
            origin_verify_secret: env.opt("ORIGIN_VERIFY_SECRET_ARN"),
        };
        http.validate()?;

        let upstream = UpstreamConfig::new(env.req("UPSTREAM_BASE_URL")?)
            .with_timeout(env.secs("PROXY_TIMEOUT_SECS", DEFAULT_PROXY_TIMEOUT_SECS)?);

        Ok(Self {
            app,
            cognito,
            http,
            upstream,
            table: env.req("SESSIONS_TABLE")?,
            secret_cache_ttl: env.secs("SECRET_CACHE_TTL_SECS", DEFAULT_SECRET_TTL_SECS)?,
            dynamodb_endpoint: if cfg!(feature = "local") {
                env.opt("DYNAMODB_ENDPOINT_URL")
            } else {
                None
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn base() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("PUBLIC_ORIGIN", "https://app.example.com"),
            (
                "COGNITO_ISSUER",
                "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_abc",
            ),
            ("COGNITO_DOMAIN", "https://auth.example.com"),
            ("COGNITO_CLIENT_ID", "cid"),
            (
                "COGNITO_CLIENT_SECRET_ARN",
                "arn:aws:secretsmanager:us-east-2:1:secret:x",
            ),
            ("SESSIONS_TABLE", "tabla"),
            ("UPSTREAM_BASE_URL", "https://api.example.com"),
        ])
    }

    fn load(m: &HashMap<&'static str, &'static str>) -> Result<Config, ConfigError> {
        Config::from_lookup(&|k| m.get(k).map(|v| (*v).to_owned()))
    }

    #[test]
    fn valores_por_defecto() {
        let c = load(&base()).unwrap();
        assert_eq!(c.cognito.redirect_uri, "https://app.example.com/auth/callback");
        assert_eq!(c.cognito.logout_uri, "https://app.example.com/");
        assert_eq!(c.cognito.http_timeout, Duration::from_secs(4));
        assert_eq!(c.app.csrf_header, "x-requested-with");
        assert_eq!(c.app.proxy_max_body, 1024 * 1024);
        assert_eq!(c.http.session_cookie, "__Host-bff_session");
        assert_eq!(c.http.origin_verify_secret, None);
        assert!(c.cognito.exposed_claims.is_empty());
        assert_eq!(c.dynamodb_endpoint, None);
    }

    #[test]
    fn rechaza_lo_invalido() {
        let caso = |k: &'static str, v: &'static str| {
            let mut m = base();
            m.insert(k, v);
            load(&m).unwrap_err()
        };
        assert_eq!(
            caso("PUBLIC_ORIGIN", "http://app.example.com"),
            ConfigError::Invalid("PUBLIC_ORIGIN")
        );
        assert_eq!(
            caso("PUBLIC_ORIGIN", "https://app.example.com/"),
            ConfigError::Invalid("PUBLIC_ORIGIN")
        );
        assert_eq!(
            caso("PUBLIC_ORIGIN", "https://app.example.com/x"),
            ConfigError::Invalid("PUBLIC_ORIGIN")
        );
        assert_eq!(
            caso("IDP_TIMEOUT_SECS", "10"),
            ConfigError::Cognito(oidc_cognito::ConfigError::TimeoutNotBelowLease)
        );
        assert_eq!(
            caso("COOKIE_NAME", "sesion"),
            ConfigError::Http(http_axum::HttpConfigError::CookieName)
        );
        assert_eq!(
            caso("AUTH_ERROR_REDIRECT_PATH", "//evil.com"),
            ConfigError::Invalid("AUTH_ERROR_REDIRECT_PATH")
        );
        assert_eq!(
            caso("LOGOUT_REDIRECT_PATH", "https://evil.com"),
            ConfigError::Invalid("LOGOUT_REDIRECT_PATH")
        );
        assert_eq!(
            caso("REFRESH_LEASE_SECS", "x"),
            ConfigError::Invalid("REFRESH_LEASE_SECS")
        );
        assert_eq!(
            caso("PROXY_TIMEOUT_SECS", "0"),
            ConfigError::Invalid("PROXY_TIMEOUT_SECS")
        );
        assert_eq!(
            caso("CSRF_HEADER_NAME", "x y"),
            ConfigError::Invalid("CSRF_HEADER_NAME")
        );
        let mut m = base();
        m.remove("SESSIONS_TABLE");
        assert_eq!(load(&m).unwrap_err(), ConfigError::Missing("SESSIONS_TABLE"));
    }

    #[test]
    fn localhost_y_claims() {
        let mut m = base();
        m.insert("PUBLIC_ORIGIN", "http://localhost:5173");
        m.insert("EXPOSED_CLAIMS", " custom:tenant_id , ,x ");
        m.insert("PROXY_MAX_BODY_BYTES", "99999999999");
        let c = load(&m).unwrap();
        assert_eq!(c.cognito.redirect_uri, "http://localhost:5173/auth/callback");
        assert_eq!(c.cognito.exposed_claims, vec!["custom:tenant_id", "x"]);
        assert_eq!(c.app.proxy_max_body, application::PROXY_MAX_BODY_HARD_CAP);
    }
}
