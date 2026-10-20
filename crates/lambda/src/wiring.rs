//! Construccion de los adaptadores reales y del router (§7.6): todo una vez, antes de
//! atender la primera peticion.

use std::future::Future;
use std::sync::Arc;

use application::App;
use application::ports::{AdapterError, Ports, SecretProvider, SecretVersions};
use oidc_cognito::{CognitoAccount, CognitoIdp};
use session_dynamodb::{DynamoPending, DynamoSessions, DynamoTickets};
use upstream_reqwest::ReqwestUpstream;

use crate::config::Config;
use crate::system::{OsRng, SystemClock};

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("Cognito no disponible al arrancar")]
    Idp(AdapterError),
    #[error("{0}")]
    Upstream(#[from] upstream_reqwest::ConfigError),
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

/// Router listo para `lambda_http::run` (o para `axum::serve` en local).
///
/// # Errors
/// `BuildError` si Cognito no responde al descargar el JWKS o la configuracion de un
/// adaptador no es valida.
pub async fn build<S: SecretProvider + 'static>(
    cfg: Config,
    secrets: Arc<S>,
    sdk: &aws_config::SdkConfig,
) -> Result<axum::Router, BuildError> {
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
        upstream: ReqwestUpstream::new(cfg.upstream)?,
        clock: SystemClock,
        rng: OsRng::default(),
    };
    let app = App::new(Arc::new(ports), cfg.app);
    Ok(http_axum::router(app, cfg.http, secrets)?)
}
