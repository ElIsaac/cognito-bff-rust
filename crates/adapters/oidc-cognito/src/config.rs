use std::time::Duration;

use url::Url;

/// Configuracion del adaptador. La arma el composition root a partir de las variables de
/// entorno (§8 del plan).
#[derive(Debug, Clone)]
pub struct CognitoConfig {
    /// `https://cognito-idp.<region>.amazonaws.com/<poolId>`.
    pub issuer: String,
    /// Dominio del Hosted UI / Managed Login, con esquema y sin barra final.
    pub domain: Url,
    pub client_id: String,
    /// Nombre o ARN del secreto con el `client_secret`.
    pub client_secret_name: String,
    /// `PUBLIC_ORIGIN + /auth/callback`.
    pub redirect_uri: String,
    /// `PUBLIC_ORIGIN + LOGOUT_REDIRECT_PATH`.
    pub logout_uri: String,
    /// Separados por espacio.
    pub scopes: String,
    /// Claims extra (lista blanca) que pasan a `UserInfo::attributes`.
    pub exposed_claims: Vec<String>,
    /// Debe ser menor que el lease de refresh (decision 42).
    pub http_timeout: Duration,
    pub jwks_cache_ttl: Duration,
    /// Intervalo minimo entre descargas del JWKS por `kid` desconocido.
    pub jwks_min_refetch: Duration,
    /// Tolerancia de reloj para `iat` y `exp`.
    pub leeway: Duration,
    /// Solo `false` en tests con un servidor local.
    pub require_https: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} debe ser una URL https")]
    NotHttps(&'static str),
    #[error("{0} vacio")]
    Empty(&'static str),
    #[error("el timeout HTTP del IdP debe ser menor que el lease de refresh")]
    TimeoutNotBelowLease,
    #[error("el issuer no tiene la forma https://cognito-idp.<region>.amazonaws.com/<pool>")]
    BadIssuer,
}

impl CognitoConfig {
    /// Comprueba invariantes que, si fallan, harian inseguro o inestable el BFF.
    ///
    /// # Errors
    /// `ConfigError` con la primera regla incumplida.
    pub fn validate(&self, refresh_lease: Duration) -> Result<(), ConfigError> {
        for (name, v) in [
            ("COGNITO_CLIENT_ID", &self.client_id),
            ("COGNITO_CLIENT_SECRET_ARN", &self.client_secret_name),
            ("OIDC_SCOPES", &self.scopes),
        ] {
            if v.trim().is_empty() {
                return Err(ConfigError::Empty(name));
            }
        }
        if self.require_https {
            if self.domain.scheme() != "https" {
                return Err(ConfigError::NotHttps("COGNITO_DOMAIN"));
            }
            for (name, v) in [
                ("redirect_uri", &self.redirect_uri),
                ("logout_uri", &self.logout_uri),
            ] {
                // Cognito solo admite http en localhost (callback de desarrollo).
                let ok = v.starts_with("https://") || v.starts_with("http://localhost");
                if !ok {
                    return Err(ConfigError::NotHttps(name));
                }
            }
            let ok_issuer = self.issuer.starts_with("https://cognito-idp.")
                && self.issuer.contains(".amazonaws.com/")
                && !self.issuer.ends_with('/');
            if !ok_issuer {
                return Err(ConfigError::BadIssuer);
            }
        }
        if self.http_timeout >= refresh_lease {
            return Err(ConfigError::TimeoutNotBelowLease);
        }
        Ok(())
    }

    pub(crate) fn endpoint(&self, path: &str) -> Url {
        let mut url = self.domain.clone();
        url.set_path(path);
        url.set_query(None);
        url
    }

    pub(crate) fn jwks_url(&self) -> String {
        format!("{}/.well-known/jwks.json", self.issuer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> CognitoConfig {
        CognitoConfig {
            issuer: "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_abc".into(),
            domain: Url::parse("https://auth.example.com").unwrap(),
            client_id: "cid".into(),
            client_secret_name: "arn:secreto".into(),
            redirect_uri: "https://app.example.com/auth/callback".into(),
            logout_uri: "https://app.example.com/".into(),
            scopes: "openid email profile".into(),
            exposed_claims: vec![],
            http_timeout: Duration::from_secs(4),
            jwks_cache_ttl: Duration::from_secs(3600),
            jwks_min_refetch: Duration::from_secs(60),
            leeway: Duration::from_secs(60),
            require_https: true,
        }
    }

    #[test]
    fn valida() {
        let lease = Duration::from_secs(10);
        assert!(cfg().validate(lease).is_ok());
        assert_eq!(
            CognitoConfig {
                http_timeout: lease,
                ..cfg()
            }
            .validate(lease),
            Err(ConfigError::TimeoutNotBelowLease)
        );
        assert_eq!(
            CognitoConfig {
                domain: Url::parse("http://auth.example.com").unwrap(),
                ..cfg()
            }
            .validate(lease),
            Err(ConfigError::NotHttps("COGNITO_DOMAIN"))
        );
        assert_eq!(
            CognitoConfig {
                redirect_uri: "http://evil.com/cb".into(),
                ..cfg()
            }
            .validate(lease),
            Err(ConfigError::NotHttps("redirect_uri"))
        );
        assert!(
            CognitoConfig {
                redirect_uri: "http://localhost:5173/auth/callback".into(),
                ..cfg()
            }
            .validate(lease)
            .is_ok()
        );
        assert_eq!(
            CognitoConfig {
                issuer: "https://evil.com/x".into(),
                ..cfg()
            }
            .validate(lease),
            Err(ConfigError::BadIssuer)
        );
    }

    #[test]
    fn endpoints() {
        assert_eq!(
            cfg().endpoint("/oauth2/token").as_str(),
            "https://auth.example.com/oauth2/token"
        );
        assert_eq!(
            cfg().jwks_url(),
            "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_abc/.well-known/jwks.json"
        );
    }
}
