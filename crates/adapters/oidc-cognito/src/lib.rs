//! `IdentityProvider` sobre Amazon Cognito (decision 45 del plan).
//!
//! - Endpoints `/oauth2/authorize`, `/oauth2/token`, `/oauth2/revoke` y `/logout` sobre el
//!   dominio del Hosted UI / Managed Login.
//! - Cliente confidencial: el `client_secret` sale de un `SecretProvider` (cache TTL) y se
//!   recarga una vez ante `invalid_client` (rotacion).
//! - El ID token se valida aqui (RS256 fijo, `iss`, `aud`, `exp`, `iat`, `token_use`, `nonce`)
//!   y solo sus claims validados salen hacia la aplicacion.
//! - `CognitoAccount`: autoservicio de cuenta (TOTP y contrasena) con el access token del
//!   usuario (decision 48).

mod account;
mod config;
mod id_token;
mod jwks;
mod token_endpoint;

use std::time::Duration;

use application::ports::{
    AdapterError, AuthorizationRequest, IdentityProvider, IdpError, RefreshGrant, SecretProvider, TokenGrant,
};
use domain::{AccessToken, AuthCode, CodeVerifier, Nonce, RefreshToken, TokenSet};

pub use account::CognitoAccount;
pub use config::{CognitoConfig, ConfigError};
use id_token::IdTokenValidator;
use jwks::JwksCache;
use token_endpoint::{TokenClient, TokenResponse};

/// Adaptador de Cognito. Se construye una vez en el composition root y se comparte.
#[derive(Debug)]
pub struct CognitoIdp<S> {
    cfg: CognitoConfig,
    tokens: TokenClient<S>,
    validator: IdTokenValidator,
}

impl<S: SecretProvider> CognitoIdp<S> {
    /// Construye el cliente HTTP y descarga el JWKS (falla rapido si Cognito no responde).
    ///
    /// # Errors
    /// `AdapterError` si no se pudo crear el cliente o descargar el JWKS.
    pub async fn new(cfg: CognitoConfig, secrets: S) -> Result<Self, AdapterError> {
        let http = reqwest::Client::builder()
            .timeout(cfg.http_timeout)
            .connect_timeout(cfg.http_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(cfg.require_https)
            .build()
            .map_err(|e| {
                tracing::error!(error = %e, "no se pudo crear el cliente HTTP de Cognito");
                AdapterError::Permanent
            })?;
        let jwks = JwksCache::new(
            http.clone(),
            cfg.jwks_url(),
            cfg.jwks_cache_ttl,
            cfg.jwks_min_refetch,
        );
        jwks.warm_up().await?;
        let validator = IdTokenValidator::new(&cfg, jwks);
        let tokens = TokenClient::new(http, &cfg, secrets);
        Ok(Self {
            cfg,
            tokens,
            validator,
        })
    }

    fn expires_in(resp: &TokenResponse) -> Duration {
        Duration::from_secs(resp.expires_in)
    }
}

impl<S: SecretProvider> IdentityProvider for CognitoIdp<S> {
    fn authorization_url(&self, req: &AuthorizationRequest) -> String {
        let mut url = self.cfg.endpoint("/oauth2/authorize");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("redirect_uri", &self.cfg.redirect_uri)
            .append_pair("scope", &self.cfg.scopes)
            .append_pair("state", &req.state.expose_secret())
            .append_pair("nonce", &req.nonce.expose_secret())
            .append_pair("code_challenge", req.code_challenge.as_str())
            .append_pair("code_challenge_method", "S256");
        url.into()
    }

    async fn exchange_code(
        &self,
        code: &AuthCode,
        verifier: &CodeVerifier,
        nonce: &Nonce,
    ) -> Result<TokenGrant, IdpError> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code.expose_secret()),
            ("redirect_uri", self.cfg.redirect_uri.as_str()),
            ("code_verifier", verifier.expose_secret()),
        ];
        let resp = self.tokens.post_token(&form).await?;
        let id_token = resp.id_token.as_deref().ok_or_else(|| {
            tracing::warn!("respuesta del token endpoint sin id_token");
            IdpError::TokenRejected
        })?;
        let user = self.validator.validate(id_token, Some(nonce)).await?;
        let refresh = resp.refresh_token.clone().ok_or_else(|| {
            tracing::warn!("respuesta del token endpoint sin refresh_token");
            IdpError::TokenRejected
        })?;
        Ok(TokenGrant {
            tokens: TokenSet {
                access: AccessToken::new(resp.access_token.clone()).map_err(|_| IdpError::TokenRejected)?,
                refresh: RefreshToken::new(refresh).map_err(|_| IdpError::TokenRejected)?,
            },
            access_expires_in: Self::expires_in(&resp),
            user,
        })
    }

    async fn refresh(&self, refresh: &RefreshToken) -> Result<RefreshGrant, IdpError> {
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.expose_secret()),
        ];
        let resp = self.tokens.post_token(&form).await?;
        // En un refresh Cognito no incluye `nonce`; el ID token se valida sin el.
        let user = match resp.id_token.as_deref() {
            Some(t) => Some(self.validator.validate(t, None).await?),
            None => None,
        };
        let rotated = match resp.refresh_token.clone() {
            Some(r) => Some(RefreshToken::new(r).map_err(|_| IdpError::TokenRejected)?),
            None => None,
        };
        Ok(RefreshGrant {
            access: AccessToken::new(resp.access_token.clone()).map_err(|_| IdpError::TokenRejected)?,
            refresh: rotated,
            access_expires_in: Self::expires_in(&resp),
            user,
        })
    }

    async fn revoke(&self, refresh: &RefreshToken) -> Result<(), IdpError> {
        self.tokens.revoke(refresh.expose_secret()).await
    }

    fn logout_url(&self) -> String {
        let mut url = self.cfg.endpoint("/logout");
        url.query_pairs_mut()
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("logout_uri", &self.cfg.logout_uri);
        url.into()
    }
}
