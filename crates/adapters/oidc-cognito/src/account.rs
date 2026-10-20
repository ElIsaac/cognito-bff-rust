use std::time::Duration;

use application::ports::{AccountError, AccountManager, AdapterError};
use domain::{AccessToken, DeviceName, Password, TotpCode, TotpSecret};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

const TARGET_PREFIX: &str = "AWSCognitoIdentityProviderService";
const CONTENT_TYPE: &str = "application/x-amz-json-1.1";

/// `AccountManager` sobre el endpoint JSON de Cognito Identity Provider
/// (`https://cognito-idp.<region>.amazonaws.com/`). Las operaciones de autoservicio se
/// autorizan con el access token del usuario: no hace falta firma `SigV4` ni secreto.
#[derive(Debug, Clone)]
pub struct CognitoAccount {
    http: reqwest::Client,
    endpoint: Url,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(rename = "__type", default)]
    kind: Option<String>,
}

#[derive(Deserialize)]
struct GetUserOut {
    #[serde(rename = "UserMFASettingList", default)]
    mfa: Vec<String>,
}

#[derive(Deserialize)]
struct AssociateOut {
    #[serde(rename = "SecretCode")]
    secret: String,
}

#[derive(Deserialize)]
struct VerifyOut {
    #[serde(rename = "Status")]
    status: String,
}

/// Traduce el `__type` de Cognito (con o sin prefijo `namespace#`) a la lista blanca.
fn classify(status: reqwest::StatusCode, kind: Option<&str>) -> AccountError {
    let name = kind.map(|k| k.rsplit('#').next().unwrap_or(k));
    match name {
        Some("CodeMismatchException") => AccountError::CodeMismatch,
        Some("ExpiredCodeException") => AccountError::CodeExpired,
        Some("NotAuthorizedException") => AccountError::NotAuthorized,
        Some("InvalidPasswordException" | "PasswordHistoryPolicyViolationException") => {
            AccountError::InvalidPassword
        }
        Some(
            "EnableSoftwareTokenMFAException"
            | "SoftwareTokenMFANotFoundException"
            | "InvalidParameterException",
        ) => AccountError::MfaSetupInvalid,
        Some("TooManyRequestsException" | "LimitExceededException" | "TooManyFailedAttemptsException") => {
            AccountError::TooManyRequests
        }
        _ if status.is_server_error() => AccountError::Adapter(AdapterError::Transient),
        _ => AccountError::Adapter(AdapterError::Permanent),
    }
}

impl CognitoAccount {
    /// `endpoint` es el origen del issuer (`https://cognito-idp.<region>.amazonaws.com`).
    ///
    /// # Errors
    /// `AdapterError::Permanent` si no se pudo crear el cliente HTTP.
    pub fn new(endpoint: Url, timeout: Duration, require_https: bool) -> Result<Self, AdapterError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(require_https)
            .build()
            .map_err(|e| {
                tracing::error!(error = %e, "no se pudo crear el cliente HTTP de cuentas");
                AdapterError::Permanent
            })?;
        Ok(Self { http, endpoint })
    }

    /// Endpoint a partir del issuer `https://cognito-idp.<region>.amazonaws.com/<pool>`.
    ///
    /// # Errors
    /// `AdapterError::Permanent` si el issuer no es una URL.
    pub fn endpoint_from_issuer(issuer: &str) -> Result<Url, AdapterError> {
        let mut url = Url::parse(issuer).map_err(|_| AdapterError::Permanent)?;
        url.set_path("/");
        url.set_query(None);
        Ok(url)
    }

    async fn call(
        &self,
        op: &'static str,
        access: &AccessToken,
        extra: Value,
    ) -> Result<Value, AccountError> {
        let mut body = json!({ "AccessToken": access.expose_secret() });
        if let (Some(b), Value::Object(e)) = (body.as_object_mut(), extra) {
            b.extend(e);
        }
        let resp = self
            .http
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE)
            .header("x-amz-target", format!("{TARGET_PREFIX}.{op}"))
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(op, timeout = e.is_timeout(), "fallo de red con Cognito (cuenta)");
                AccountError::Adapter(AdapterError::Transient)
            })?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .map_err(|_| AccountError::Adapter(AdapterError::Transient))?;
        if status.is_success() {
            return serde_json::from_slice(&bytes).map_err(|_| {
                tracing::error!(op, "respuesta de Cognito (cuenta) con formato invalido");
                AccountError::Adapter(AdapterError::Permanent)
            });
        }
        let kind = serde_json::from_slice::<ErrorBody>(&bytes)
            .ok()
            .and_then(|e| e.kind);
        let err = classify(status, kind.as_deref());
        tracing::warn!(op, %status, kind = kind.as_deref().unwrap_or("-"), "Cognito rechazo la operacion de cuenta");
        Err(err)
    }

    fn parse<T: for<'de> Deserialize<'de>>(op: &'static str, v: Value) -> Result<T, AccountError> {
        serde_json::from_value(v).map_err(|_| {
            tracing::error!(op, "respuesta de Cognito (cuenta) sin los campos esperados");
            AccountError::Adapter(AdapterError::Permanent)
        })
    }
}

impl AccountManager for CognitoAccount {
    async fn mfa_status(&self, access: &AccessToken) -> Result<bool, AccountError> {
        let v = self.call("GetUser", access, json!({})).await?;
        let out: GetUserOut = Self::parse("GetUser", v)?;
        Ok(out.mfa.iter().any(|m| m == "SOFTWARE_TOKEN_MFA"))
    }

    async fn associate_totp(&self, access: &AccessToken) -> Result<TotpSecret, AccountError> {
        let v = self.call("AssociateSoftwareToken", access, json!({})).await?;
        let out: AssociateOut = Self::parse("AssociateSoftwareToken", v)?;
        TotpSecret::new(out.secret).map_err(|_| {
            tracing::error!("secreto TOTP de Cognito con formato inesperado");
            AccountError::Adapter(AdapterError::Permanent)
        })
    }

    async fn verify_totp(
        &self,
        access: &AccessToken,
        code: &TotpCode,
        device: Option<&DeviceName>,
    ) -> Result<(), AccountError> {
        let mut extra = json!({ "UserCode": code.expose_secret() });
        if let (Some(d), Some(m)) = (device, extra.as_object_mut()) {
            m.insert("FriendlyDeviceName".into(), Value::String(d.as_str().to_owned()));
        }
        let v = self.call("VerifySoftwareToken", access, extra).await?;
        let out: VerifyOut = Self::parse("VerifySoftwareToken", v)?;
        if out.status == "SUCCESS" {
            Ok(())
        } else {
            Err(AccountError::CodeMismatch)
        }
    }

    async fn set_totp(&self, access: &AccessToken, enabled: bool) -> Result<(), AccountError> {
        let extra = json!({ "SoftwareTokenMfaSettings": { "Enabled": enabled, "PreferredMfa": enabled } });
        self.call("SetUserMFAPreference", access, extra).await.map(|_| ())
    }

    async fn change_password(
        &self,
        access: &AccessToken,
        previous: &Password,
        proposed: &Password,
    ) -> Result<(), AccountError> {
        let extra = json!({
            "PreviousPassword": previous.expose_secret(),
            "ProposedPassword": proposed.expose_secret(),
        });
        self.call("ChangePassword", access, extra).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn clasificacion() {
        let bad = StatusCode::BAD_REQUEST;
        assert_eq!(
            classify(bad, Some("com.amazonaws#CodeMismatchException")),
            AccountError::CodeMismatch
        );
        assert_eq!(
            classify(bad, Some("NotAuthorizedException")),
            AccountError::NotAuthorized
        );
        assert_eq!(
            classify(bad, Some("PasswordHistoryPolicyViolationException")),
            AccountError::InvalidPassword
        );
        assert_eq!(
            classify(bad, Some("SoftwareTokenMFANotFoundException")),
            AccountError::MfaSetupInvalid
        );
        assert_eq!(
            classify(bad, Some("LimitExceededException")),
            AccountError::TooManyRequests
        );
        assert_eq!(
            classify(StatusCode::INTERNAL_SERVER_ERROR, Some("InternalErrorException")),
            AccountError::Adapter(AdapterError::Transient)
        );
        assert_eq!(
            classify(bad, Some("ResourceNotFoundException")),
            AccountError::Adapter(AdapterError::Permanent)
        );
        assert_eq!(
            classify(bad, None),
            AccountError::Adapter(AdapterError::Permanent)
        );
    }

    #[test]
    fn endpoint_desde_issuer() {
        let e =
            CognitoAccount::endpoint_from_issuer("https://cognito-idp.us-east-2.amazonaws.com/us-east-2_abc")
                .unwrap();
        assert_eq!(e.as_str(), "https://cognito-idp.us-east-2.amazonaws.com/");
    }
}
