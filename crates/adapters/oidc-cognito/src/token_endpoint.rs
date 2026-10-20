use application::ports::{AdapterError, IdpError, SecretProvider};
use reqwest::StatusCode;
use serde::Deserialize;

use crate::CognitoConfig;

#[derive(Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    pub token_type: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

/// Resultado de una llamada autenticada al endpoint, antes de interpretar el cuerpo.
enum Outcome {
    Ok(reqwest::Response),
    InvalidClient,
    Failed(IdpError),
}

/// Llamadas con autenticacion de cliente (`client_secret_basic`) a `/oauth2/token` y
/// `/oauth2/revoke`.
pub(crate) struct TokenClient<S> {
    http: reqwest::Client,
    token_url: String,
    revoke_url: String,
    client_id: String,
    secret_name: String,
    secrets: S,
}

impl<S> std::fmt::Debug for TokenClient<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenClient")
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

fn classify(status: StatusCode, error: Option<&str>) -> Outcome {
    match (status, error) {
        (_, Some("invalid_client")) | (StatusCode::UNAUTHORIZED, None) => Outcome::InvalidClient,
        (_, Some("invalid_grant")) => Outcome::Failed(IdpError::InvalidGrant),
        (s, _) if s == StatusCode::TOO_MANY_REQUESTS || s.is_server_error() => {
            Outcome::Failed(IdpError::Adapter(AdapterError::Transient))
        }
        _ => Outcome::Failed(IdpError::Adapter(AdapterError::Permanent)),
    }
}

impl<S: SecretProvider> TokenClient<S> {
    pub(crate) fn new(http: reqwest::Client, cfg: &CognitoConfig, secrets: S) -> Self {
        Self {
            http,
            token_url: cfg.endpoint("/oauth2/token").into(),
            revoke_url: cfg.endpoint("/oauth2/revoke").into(),
            client_id: cfg.client_id.clone(),
            secret_name: cfg.client_secret_name.clone(),
            secrets,
        }
    }

    async fn call(&self, url: &str, form: &[(&str, &str)]) -> Result<Outcome, IdpError> {
        let secret = self.secrets.get(&self.secret_name).await?;
        let resp = self
            .http
            .post(url)
            .basic_auth(&self.client_id, Some(secret.current.expose_secret()))
            .form(form)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(timeout = e.is_timeout(), "fallo de red con Cognito");
                IdpError::Adapter(AdapterError::Transient)
            })?;
        let status = resp.status();
        if status.is_success() {
            return Ok(Outcome::Ok(resp));
        }
        let error = resp.json::<ErrorResponse>().await.ok().map(|e| e.error);
        tracing::warn!(%status, error = error.as_deref().unwrap_or("-"), "Cognito rechazo la peticion");
        Ok(classify(status, error.as_deref()))
    }

    /// Un reintento tras recargar el secreto si Cognito responde `invalid_client` (el
    /// secreto pudo rotar desde que se cacheo).
    async fn call_with_retry(&self, url: &str, form: &[(&str, &str)]) -> Result<reqwest::Response, IdpError> {
        match self.call(url, form).await? {
            Outcome::Ok(r) => Ok(r),
            Outcome::Failed(e) => Err(e),
            Outcome::InvalidClient => {
                self.secrets.invalidate(&self.secret_name);
                match self.call(url, form).await? {
                    Outcome::Ok(r) => Ok(r),
                    Outcome::Failed(e) => Err(e),
                    Outcome::InvalidClient => {
                        tracing::error!("invalid_client persistente: revisa el client secret");
                        Err(IdpError::Adapter(AdapterError::Permanent))
                    }
                }
            }
        }
    }

    pub(crate) async fn post_token(&self, form: &[(&str, &str)]) -> Result<TokenResponse, IdpError> {
        let resp = self.call_with_retry(&self.token_url, form).await?;
        let body: TokenResponse = resp.json().await.map_err(|_| {
            tracing::error!("respuesta del token endpoint con formato invalido");
            IdpError::Adapter(AdapterError::Permanent)
        })?;
        if !body.token_type.eq_ignore_ascii_case("bearer") {
            tracing::error!("token_type inesperado");
            return Err(IdpError::TokenRejected);
        }
        Ok(body)
    }

    pub(crate) async fn revoke(&self, refresh: &str) -> Result<(), IdpError> {
        self.call_with_retry(&self.revoke_url, &[("token", refresh)])
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clasificacion() {
        assert!(matches!(
            classify(StatusCode::BAD_REQUEST, Some("invalid_client")),
            Outcome::InvalidClient
        ));
        assert!(matches!(
            classify(StatusCode::UNAUTHORIZED, None),
            Outcome::InvalidClient
        ));
        assert!(matches!(
            classify(StatusCode::BAD_REQUEST, Some("invalid_grant")),
            Outcome::Failed(IdpError::InvalidGrant)
        ));
        assert!(matches!(
            classify(StatusCode::SERVICE_UNAVAILABLE, None),
            Outcome::Failed(IdpError::Adapter(AdapterError::Transient))
        ));
        assert!(matches!(
            classify(StatusCode::TOO_MANY_REQUESTS, None),
            Outcome::Failed(IdpError::Adapter(AdapterError::Transient))
        ));
        assert!(matches!(
            classify(StatusCode::BAD_REQUEST, Some("unsupported_grant_type")),
            Outcome::Failed(IdpError::Adapter(AdapterError::Permanent))
        ));
    }
}
