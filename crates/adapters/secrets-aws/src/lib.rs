//! `SecretProvider` sobre AWS Secrets Manager.
//!
//! - Cache con TTL por secreto (600 s por defecto).
//! - `invalidate` fuerza la recarga en la siguiente `get`.
//! - Single-flight: varias `get` simultaneas con la cache vacia hacen una sola llamada.
//! - Los errores se mapean a `AdapterError` (throttling, 5xx y timeouts son `Transient`);
//!   nunca se registran valores de secretos.
//!
//! Con la feature `local` se ofrece `EnvSecretProvider`, que lee los secretos del entorno.

mod aws;
mod cache;
#[cfg(feature = "local")]
mod env;

pub use aws::SecretsManagerFetcher;
pub use cache::{CachedSecrets, DEFAULT_CACHE_TTL, SecretFetcher};
#[cfg(feature = "local")]
pub use env::EnvSecretProvider;

/// Proveedor de produccion: Secrets Manager con cache.
pub type SecretsManagerProvider = CachedSecrets<SecretsManagerFetcher>;

/// Etapas de version que se leen.
pub(crate) const STAGE_CURRENT: &str = "AWSCURRENT";
pub(crate) const STAGE_PREVIOUS: &str = "AWSPREVIOUS";

impl SecretsManagerProvider {
    /// Proveedor con el TTL de cache por defecto.
    pub fn from_client(client: aws_sdk_secretsmanager::Client) -> Self {
        Self::new(SecretsManagerFetcher::new(client), DEFAULT_CACHE_TTL)
    }
}
