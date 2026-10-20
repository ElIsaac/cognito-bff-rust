//! Composition root del BFF (§4.1, §7.6, §8).
//!
//! En Lambda: secretos de Secrets Manager con cache y `lambda_http::run`. Con la feature
//! `local`: secretos del entorno, `DYNAMODB_ENDPOINT_URL` y un servidor axum en
//! `LOCAL_ADDR` (por omision `127.0.0.1:8787`).

mod config;
mod system;
mod wiring;

use std::sync::Arc;

use config::Config;

type Error = Box<dyn std::error::Error + Send + Sync>;

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(false)
        .with_target(false)
        .with_env_filter(filter)
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    init_tracing();
    let cfg = Config::from_lookup(&|k| std::env::var(k).ok()).inspect_err(|e| {
        tracing::error!(error = %e, "configuracion invalida");
    })?;
    let sdk = aws_config::load_from_env().await;
    run(cfg, &sdk).await
}

#[cfg(not(feature = "local"))]
async fn run(cfg: Config, sdk: &aws_config::SdkConfig) -> Result<(), Error> {
    use secrets_aws::{CachedSecrets, SecretsManagerFetcher};

    let fetcher = SecretsManagerFetcher::new(aws_sdk_secretsmanager::Client::new(sdk));
    let secrets = Arc::new(CachedSecrets::new(fetcher, cfg.secret_cache_ttl));
    let router = wiring::build(cfg, secrets, sdk).await.inspect_err(|e| {
        tracing::error!(error = %e, "no se pudo construir el BFF");
    })?;
    lambda_http::run(router.layer(axum::middleware::map_request(apigw_request_id))).await
}

/// Decision 17: `X-Request-ID` es el `requestId` de API Gateway; el que mande el cliente se
/// descarta.
#[cfg(not(feature = "local"))]
async fn apigw_request_id(mut req: axum::extract::Request) -> axum::extract::Request {
    use lambda_http::RequestExt;
    use lambda_http::request::RequestContext;

    let id = match req.request_context_ref() {
        Some(RequestContext::ApiGatewayV2(c)) => c.request_id.clone(),
        _ => None,
    };
    let value = id.and_then(|v| axum::http::HeaderValue::from_str(&v).ok());
    let headers = req.headers_mut();
    match value {
        Some(v) => {
            headers.insert("x-request-id", v);
        }
        None => {
            headers.remove("x-request-id");
        }
    }
    req
}

#[cfg(feature = "local")]
async fn run(cfg: Config, sdk: &aws_config::SdkConfig) -> Result<(), Error> {
    let secrets = Arc::new(secrets_aws::EnvSecretProvider::new());
    let router = wiring::build(cfg, secrets, sdk).await?;
    let addr = std::env::var("LOCAL_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "BFF local escuchando");
    axum::serve(listener, router).await?;
    Ok(())
}
