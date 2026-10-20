use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use application::ports::IdpError;
use domain::{Email, GroupName, Nonce, Subject, UserInfo};
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;

use crate::CognitoConfig;
use crate::jwks::JwksCache;

#[derive(Deserialize)]
struct IdClaims {
    sub: String,
    iat: u64,
    token_use: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<Value>,
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "cognito:groups", default)]
    groups: Option<Vec<String>>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

/// Valida ID tokens de Cognito y extrae `UserInfo`.
#[derive(Debug)]
pub(crate) struct IdTokenValidator {
    jwks: JwksCache,
    validation: Validation,
    leeway_secs: u64,
    exposed_claims: Vec<String>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `email_verified` llega como booleano o como la cadena `"true"`.
fn is_verified(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    }
}

impl IdTokenValidator {
    pub(crate) fn new(cfg: &CognitoConfig, jwks: JwksCache) -> Self {
        // Algoritmo fijo: el `alg` de la cabecera no puede elegir otro (ni `none`, ni HS256
        // con la llave publica como secreto).
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[cfg.issuer.as_str()]);
        validation.set_audience(&[cfg.client_id.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub", "iat"]);
        validation.leeway = cfg.leeway.as_secs();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        Self {
            jwks,
            validation,
            leeway_secs: cfg.leeway.as_secs(),
            exposed_claims: cfg.exposed_claims.clone(),
        }
    }

    /// `nonce = Some` en el canje del code (obligatorio y debe coincidir); `None` en un
    /// refresh (Cognito no lo incluye).
    pub(crate) async fn validate(&self, token: &str, nonce: Option<&Nonce>) -> Result<UserInfo, IdpError> {
        let header = decode_header(token).map_err(|_| reject("cabecera ilegible"))?;
        if header.alg != Algorithm::RS256 {
            return Err(reject("alg distinto de RS256"));
        }
        let kid = header.kid.ok_or_else(|| reject("sin kid"))?;
        let key = self
            .jwks
            .key(&kid)
            .await
            .map_err(IdpError::Adapter)?
            .ok_or_else(|| reject("kid desconocido"))?;
        let data = decode::<IdClaims>(token, &key, &self.validation).map_err(|e| {
            tracing::warn!(kind = ?e.kind(), "ID token rechazado");
            IdpError::TokenRejected
        })?;
        let c = data.claims;

        if c.token_use != "id" {
            return Err(reject("token_use distinto de id"));
        }
        if c.iat > now_secs().saturating_add(self.leeway_secs) {
            return Err(reject("iat en el futuro"));
        }
        if let Some(expected) = nonce {
            let ok = c.nonce.as_deref().is_some_and(|n| expected.matches_claim(n));
            if !ok {
                return Err(reject("nonce no coincide"));
            }
        }

        let sub = Subject::new(c.sub).map_err(|_| reject("sub invalido"))?;
        let email = if is_verified(c.email_verified.as_ref()) {
            c.email.and_then(|e| Email::new(e).ok())
        } else {
            None
        };
        let groups = c
            .groups
            .unwrap_or_default()
            .into_iter()
            .filter_map(|g| GroupName::new(g).ok())
            .collect();
        let attributes = self.exposed_claims.iter().filter_map(|k| match c.extra.get(k) {
            Some(Value::String(v)) => Some((k.clone(), v.clone())),
            _ => None,
        });
        Ok(UserInfo::new(sub, email, c.name, groups).with_attributes(attributes))
    }
}

fn reject(reason: &'static str) -> IdpError {
    tracing::warn!(reason, "ID token rechazado");
    IdpError::TokenRejected
}
