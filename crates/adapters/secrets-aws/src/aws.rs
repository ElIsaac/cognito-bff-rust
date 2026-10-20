use application::ports::{AdapterError, SecretValue};
use aws_sdk_secretsmanager::Client;
use aws_sdk_secretsmanager::config::http::HttpResponse;
use aws_sdk_secretsmanager::error::{ProvideErrorMetadata, SdkError};

use crate::cache::SecretFetcher;

const SERVER_ERROR_MIN_STATUS: u16 = 500;
const NOT_FOUND_CODE: &str = "ResourceNotFoundException";
const THROTTLING_CODES: &[&str] = &[
    "ThrottlingException",
    "RequestLimitExceeded",
    "InternalServiceError",
    "ServiceUnavailable",
];

/// Llamada real a `GetSecretValue`.
#[derive(Debug, Clone)]
pub struct SecretsManagerFetcher {
    client: Client,
}

impl SecretsManagerFetcher {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

fn classify<E: ProvideErrorMetadata>(e: &SdkError<E, HttpResponse>) -> AdapterError {
    let code = e.code();
    let transient = match e {
        SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) => true,
        SdkError::ServiceError(se) => {
            se.raw().status().as_u16() >= SERVER_ERROR_MIN_STATUS
                || code.is_some_and(|c| THROTTLING_CODES.contains(&c))
        }
        SdkError::ResponseError(re) => re.raw().status().as_u16() >= SERVER_ERROR_MIN_STATUS,
        _ => false,
    };
    tracing::warn!(
        code = code.unwrap_or("none"),
        transient,
        "fallo de Secrets Manager"
    );
    if transient {
        AdapterError::Transient
    } else {
        AdapterError::Permanent
    }
}

impl SecretFetcher for SecretsManagerFetcher {
    async fn fetch(&self, name: &str, stage: &str) -> Result<Option<SecretValue>, AdapterError> {
        let res = self
            .client
            .get_secret_value()
            .secret_id(name)
            .version_stage(stage)
            .send()
            .await;
        match res {
            Ok(out) => {
                let value = out.secret_string.map(SecretValue::new);
                if value.is_none() {
                    tracing::error!("el secreto no tiene SecretString");
                }
                value.map(Some).ok_or(AdapterError::Permanent)
            }
            // Sin esa etapa (p. ej. nunca se roto): no es un error.
            Err(e) if e.code() == Some(NOT_FOUND_CODE) && stage == crate::STAGE_PREVIOUS => Ok(None),
            Err(e) => Err(classify(&e)),
        }
    }
}
