//! Construccion de los adaptadores reales y del router (§7.6): todo una vez, antes de
//! atender la primera peticion.

use std::future::Future;
use std::sync::Arc;

use application::App;
use application::ports::{AdapterError, Ports, SecretProvider, SecretVersions};
use oidc_cognito::{CognitoAccount, CognitoIdp};
use session_dynamodb::{DynamoPending, DynamoSessions, DynamoTickets};
use upstream_reqwest::{AwsIamSigner, ReqwestUpstream};

use crate::config::{Config, UpstreamAuth};
use crate::system::{OsRng, SystemClock};

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("Cognito no disponible al arrancar")]
    Idp(AdapterError),
    #[error("no se pudo leer el secreto {name} al arrancar")]
    Secret {
        name: &'static str,
        source: AdapterError,
    },
    #[error("{0}")]
    Upstream(#[from] upstream_reqwest::ConfigError),
    #[error("UPSTREAM_AUTH=aws_iam necesita credenciales AWS y el SDK no tiene proveedor")]
    NoCredentials,
    #[error("{0}")]
    Http(#[from] http_axum::HttpConfigError),
}

/// Un mismo proveedor de secretos compartido por el `IdP` y por `X-Origin-Verify`.
#[derive(Debug)]
pub struct SharedSecrets<S>(pub Arc<S>);

impl<S: SecretProvider> SecretProvider for SharedSecrets<S> {
    fn get(&self, name: &str) -> impl Future<Output = Result<SecretVersions, AdapterError>> + Send {
        self.0.get(name)
    }

    fn invalidate(&self, name: &str) {
        self.0.invalidate(name);
    }
}

#[derive(Debug)]
pub struct BffPorts<S: SecretProvider> {
    idp: CognitoIdp<SharedSecrets<S>>,
    account: CognitoAccount,
    sessions: DynamoSessions,
    pending: DynamoPending,
    tickets: DynamoTickets,
    upstream: ReqwestUpstream,
    clock: SystemClock,
    rng: OsRng,
}

impl<S: SecretProvider + 'static> Ports for BffPorts<S> {
    type Idp = CognitoIdp<SharedSecrets<S>>;
    type Account = CognitoAccount;
    type Sessions = DynamoSessions;
    type Pending = DynamoPending;
    type Tickets = DynamoTickets;
    type Upstream = ReqwestUpstream;
    type Clock = SystemClock;
    type Rng = OsRng;

    fn idp(&self) -> &Self::Idp {
        &self.idp
    }

    fn account(&self) -> &Self::Account {
        &self.account
    }

    fn sessions(&self) -> &Self::Sessions {
        &self.sessions
    }

    fn pending(&self) -> &Self::Pending {
        &self.pending
    }

    fn tickets(&self) -> &Self::Tickets {
        &self.tickets
    }

    fn upstream(&self) -> &Self::Upstream {
        &self.upstream
    }

    fn clock(&self) -> &Self::Clock {
        &self.clock
    }

    fn rng(&self) -> &Self::Rng {
        &self.rng
    }
}

/// Lee un secreto antes de atender trafico: un permiso o un nombre equivocado falla el
/// arranque (y se ve en el despliegue) en vez de la primera peticion.
async fn preload<S: SecretProvider>(secrets: &S, name: &'static str, id: &str) -> Result<(), BuildError> {
    secrets
        .get(id)
        .await
        .map(|_| ())
        .map_err(|source| BuildError::Secret { name, source })
}

/// Router listo para `lambda_http::run` (o para `axum::serve` en local).
///
/// # Errors
/// `BuildError` si no se puede leer el secreto del cliente o el de `X-Origin-Verify`, si
/// Cognito no responde al descargar el JWKS o si la configuracion de un adaptador no es
/// valida.
pub async fn build<S: SecretProvider + 'static>(
    cfg: Config,
    secrets: Arc<S>,
    sdk: &aws_config::SdkConfig,
) -> Result<axum::Router, BuildError> {
    preload(
        &*secrets,
        "COGNITO_CLIENT_SECRET_ARN",
        &cfg.cognito.client_secret_name,
    )
    .await?;
    if let Some(name) = &cfg.http.origin_verify_secret {
        preload(&*secrets, "ORIGIN_VERIFY_SECRET_ARN", name).await?;
    }

    let mut upstream_cfg = cfg.upstream;
    if let UpstreamAuth::AwsIam { token_header, region } = &cfg.upstream_auth {
        let credentials = sdk.credentials_provider().ok_or(BuildError::NoCredentials)?;
        upstream_cfg =
            upstream_cfg.with_aws_iam(AwsIamSigner::new(token_header, region.clone(), credentials)?);
    }

    let mut ddb = aws_sdk_dynamodb::config::Builder::from(sdk);
    if let Some(endpoint) = &cfg.dynamodb_endpoint {
        ddb = ddb.endpoint_url(endpoint);
    }
    let ddb = aws_sdk_dynamodb::Client::from_conf(ddb.build());

    let idp = CognitoIdp::new(cfg.cognito.clone(), SharedSecrets(Arc::clone(&secrets)))
        .await
        .map_err(BuildError::Idp)?;
    let endpoint = CognitoAccount::endpoint_from_issuer(&cfg.cognito.issuer).map_err(BuildError::Idp)?;
    let account = CognitoAccount::new(endpoint, cfg.cognito.http_timeout, true).map_err(BuildError::Idp)?;
    let ports = BffPorts {
        idp,
        account,
        sessions: DynamoSessions::new(ddb.clone(), &cfg.table),
        pending: DynamoPending::new(ddb.clone(), &cfg.table),
        tickets: DynamoTickets::new(ddb, &cfg.table),
        upstream: ReqwestUpstream::new(upstream_cfg)?,
        clock: SystemClock,
        rng: OsRng::default(),
    };
    let app = App::new(Arc::new(ports), cfg.app);
    Ok(http_axum::router(app, cfg.http, secrets)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use application::ports::SecretValue;

    struct Secretos(Result<(), AdapterError>);

    // Sincrono por dentro, como `EnvSecretProvider`.
    #[allow(clippy::unused_async_trait_impl)]
    impl SecretProvider for Secretos {
        async fn get(&self, _: &str) -> Result<SecretVersions, AdapterError> {
            self.0.map(|()| SecretVersions {
                current: SecretValue::new("valor".to_owned()),
                previous: None,
            })
        }

        fn invalidate(&self, _: &str) {}
    }

    #[tokio::test]
    async fn precarga_ok_y_error_nombra_la_variable() {
        assert!(
            preload(&Secretos(Ok(())), "COGNITO_CLIENT_SECRET_ARN", "x")
                .await
                .is_ok()
        );
        let e = preload(
            &Secretos(Err(AdapterError::Permanent)),
            "ORIGIN_VERIFY_SECRET_ARN",
            "x",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            e,
            BuildError::Secret {
                name: "ORIGIN_VERIFY_SECRET_ARN",
                source: AdapterError::Permanent
            }
        ));
        let msg = e.to_string();
        assert!(
            msg.contains("ORIGIN_VERIFY_SECRET_ARN") && !msg.contains("valor"),
            "{msg}"
        );
    }
}
