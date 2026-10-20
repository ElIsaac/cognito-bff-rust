use std::collections::HashMap;
use std::time::{Duration, Instant};

use application::ports::AdapterError;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(rename = "use", default)]
    use_: Option<String>,
    n: String,
    e: String,
}

struct Snapshot {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Instant,
}

/// JWKS de Cognito en memoria. Se refresca al vencer el TTL o ante un `kid` desconocido,
/// como mucho un intento por `min_refetch`, haya salido bien o mal: ni un atacante con
/// `kid` inventados ni un JWKS caido provocan descargas en bucle. La descarga corre fuera
/// del lock del snapshot, asi que los `kid` conocidos se siguen validando mientras tanto.
pub(crate) struct JwksCache {
    http: reqwest::Client,
    url: String,
    ttl: Duration,
    min_refetch: Duration,
    state: RwLock<Option<Snapshot>>,
    /// Single-flight de las descargas y hora del ultimo intento (exitoso o no).
    last_attempt: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl JwksCache {
    pub(crate) fn new(http: reqwest::Client, url: String, ttl: Duration, min_refetch: Duration) -> Self {
        Self {
            http,
            url,
            ttl,
            min_refetch,
            state: RwLock::new(None),
            last_attempt: Mutex::new(None),
        }
    }

    pub(crate) async fn warm_up(&self) -> Result<(), AdapterError> {
        let mut attempt = self.last_attempt.lock().await;
        *attempt = Some(Instant::now());
        let snap = self.fetch().await?;
        *self.state.write().await = Some(snap);
        Ok(())
    }

    /// Llave para `kid`, refrescando el JWKS si hace falta.
    pub(crate) async fn key(&self, kid: &str) -> Result<Option<DecodingKey>, AdapterError> {
        if let Some(k) = self.lookup(kid, true).await {
            return Ok(Some(k));
        }
        let mut attempt = self.last_attempt.lock().await;
        // Otra tarea pudo refrescar mientras esperabamos el turno.
        if let Some(k) = self.lookup(kid, true).await {
            return Ok(Some(k));
        }
        let throttled = attempt.is_some_and(|t| t.elapsed() < self.min_refetch);
        if !throttled {
            *attempt = Some(Instant::now());
            match self.fetch().await {
                Ok(snap) => *self.state.write().await = Some(snap),
                Err(e) if self.state.read().await.is_none() => return Err(e),
                // Con un JWKS vencido pero presente se sigue validando con el anterior.
                Err(_) => tracing::warn!("no se pudo refrescar el JWKS; se usa el anterior"),
            }
        }
        drop(attempt);
        // Vencido o no, el ultimo snapshot es lo mejor que hay hasta el siguiente intento.
        match self.lookup(kid, false).await {
            Some(k) => Ok(Some(k)),
            None if self.state.read().await.is_none() => Err(AdapterError::Transient),
            None => Ok(None),
        }
    }

    async fn lookup(&self, kid: &str, fresh_only: bool) -> Option<DecodingKey> {
        let guard = self.state.read().await;
        let s = guard.as_ref()?;
        if fresh_only && s.fetched_at.elapsed() >= self.ttl {
            return None;
        }
        s.keys.get(kid).cloned()
    }

    async fn fetch(&self) -> Result<Snapshot, AdapterError> {
        let resp = self.http.get(&self.url).send().await.map_err(|e| {
            tracing::warn!(error = %e, "fallo al descargar el JWKS");
            AdapterError::Transient
        })?;
        if !resp.status().is_success() {
            tracing::warn!(status = %resp.status(), "JWKS respondio con error");
            return Err(AdapterError::Transient);
        }
        let set: JwkSet = resp.json().await.map_err(|e| {
            tracing::error!(error = %e, "JWKS con formato invalido");
            AdapterError::Permanent
        })?;
        let mut keys = HashMap::new();
        for k in set.keys {
            let usable = k.kty == "RSA"
                && k.alg.as_deref().is_none_or(|a| a == "RS256")
                && k.use_.as_deref().is_none_or(|u| u == "sig");
            if !usable {
                continue;
            }
            match DecodingKey::from_rsa_components(&k.n, &k.e) {
                Ok(dk) => {
                    keys.insert(k.kid, dk);
                }
                Err(e) => tracing::warn!(error = %e, kid = %k.kid, "llave del JWKS descartada"),
            }
        }
        if keys.is_empty() {
            tracing::error!("JWKS sin llaves RS256 utilizables");
            return Err(AdapterError::Permanent);
        }
        Ok(Snapshot {
            keys,
            fetched_at: Instant::now(),
        })
    }
}
