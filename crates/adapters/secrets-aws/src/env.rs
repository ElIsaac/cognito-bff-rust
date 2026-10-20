use std::sync::Arc;

use application::ports::{AdapterError, SecretProvider, SecretValue, SecretVersions};

pub const CLIENT_SECRET_VAR: &str = "COGNITO_CLIENT_SECRET";
pub const ORIGIN_VERIFY_VAR: &str = "ORIGIN_VERIFY_SECRET";
const PREVIOUS_SUFFIX: &str = "_PREVIOUS";

type Lookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Lee los secretos de variables de entorno (solo desarrollo local; sin cache).
///
/// Mapeo del nombre logico a variable (sin distinguir mayusculas):
/// - contiene `client` -> `COGNITO_CLIENT_SECRET`
/// - contiene `origin` -> `ORIGIN_VERIFY_SECRET`
/// - cualquier otro nombre es `Permanent`.
///
/// El valor anterior (`previous`) se toma de la misma variable con sufijo `_PREVIOUS`
/// (`COGNITO_CLIENT_SECRET_PREVIOUS`), si existe.
#[derive(Clone)]
pub struct EnvSecretProvider {
    lookup: Lookup,
}

impl std::fmt::Debug for EnvSecretProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnvSecretProvider")
    }
}

impl Default for EnvSecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvSecretProvider {
    /// Lee del entorno del proceso.
    pub fn new() -> Self {
        Self::with_lookup(|k| std::env::var(k).ok())
    }

    /// Con una fuente propia de variables (tests).
    pub fn with_lookup(f: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        Self { lookup: Arc::new(f) }
    }

    /// Variable de entorno que corresponde a un nombre logico.
    pub fn var_for(name: &str) -> Option<&'static str> {
        let n = name.to_ascii_lowercase();
        if n.contains("client") {
            Some(CLIENT_SECRET_VAR)
        } else if n.contains("origin") {
            Some(ORIGIN_VERIFY_VAR)
        } else {
            None
        }
    }
}

// Lee variables de entorno de forma sincrona pero implementa un puerto asincrono.
#[allow(clippy::unused_async_trait_impl)]
impl SecretProvider for EnvSecretProvider {
    async fn get(&self, name: &str) -> Result<SecretVersions, AdapterError> {
        let Some(var) = Self::var_for(name) else {
            tracing::error!("nombre de secreto sin variable de entorno asociada");
            return Err(AdapterError::Permanent);
        };
        let Some(current) = (self.lookup)(var).filter(|v| !v.is_empty()) else {
            tracing::error!(var, "variable de entorno del secreto no definida");
            return Err(AdapterError::Permanent);
        };
        let previous = (self.lookup)(&format!("{var}{PREVIOUS_SUFFIX}")).filter(|v| !v.is_empty());
        Ok(SecretVersions {
            current: SecretValue::new(current),
            previous: previous.map(SecretValue::new),
        })
    }

    fn invalidate(&self, _name: &str) {}
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn con(vars: &[(&str, &str)]) -> EnvSecretProvider {
        let m: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        EnvSecretProvider::with_lookup(move |k| m.get(k).cloned())
    }

    #[tokio::test]
    async fn mapea_nombres_a_variables() {
        let p = con(&[
            (CLIENT_SECRET_VAR, "c"),
            ("COGNITO_CLIENT_SECRET_PREVIOUS", "c0"),
            (ORIGIN_VERIFY_VAR, "o"),
        ]);
        let c = p
            .get("arn:aws:secretsmanager:us-east-2:1:secret:bff/cognito-client-AbC")
            .await
            .unwrap();
        assert_eq!(c.current.expose_secret(), "c");
        assert_eq!(c.previous.unwrap().expose_secret(), "c0");
        let o = p.get("bff/ORIGIN-verify").await.unwrap();
        assert_eq!(o.current.expose_secret(), "o");
        assert!(o.previous.is_none());
    }

    #[tokio::test]
    async fn nombre_desconocido_o_variable_ausente_es_permanente() {
        let p = con(&[(CLIENT_SECRET_VAR, "c"), (ORIGIN_VERIFY_VAR, "")]);
        assert_eq!(p.get("otro").await.err(), Some(AdapterError::Permanent));
        assert_eq!(p.get("origin").await.err(), Some(AdapterError::Permanent));
        assert_eq!(con(&[]).get("client").await.err(), Some(AdapterError::Permanent));
    }
}
