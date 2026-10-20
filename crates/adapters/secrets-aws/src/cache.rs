use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use application::ports::{AdapterError, SecretProvider, SecretValue, SecretVersions};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::Instant;

use crate::{STAGE_CURRENT, STAGE_PREVIOUS};

/// TTL de cache por defecto.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(600);

/// Origen de los secretos: una llamada por (nombre, etapa). Es la unica costura con el SDK.
pub trait SecretFetcher: Send + Sync + 'static {
    /// `Ok(None)` si la etapa no existe.
    fn fetch(
        &self,
        name: &str,
        stage: &str,
    ) -> impl std::future::Future<Output = Result<Option<SecretValue>, AdapterError>> + Send;
}

#[derive(Debug, Default)]
struct Entry {
    /// El lock se mantiene durante la carga: las demas `get` esperan y reutilizan el
    /// resultado (single-flight por nombre).
    value: AsyncMutex<Option<(SecretVersions, Instant)>>,
}

/// Cache con TTL e invalidacion sobre cualquier `SecretFetcher`.
#[derive(Debug)]
pub struct CachedSecrets<F> {
    fetcher: F,
    ttl: Duration,
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}

impl<F: SecretFetcher> CachedSecrets<F> {
    pub fn new(fetcher: F, ttl: Duration) -> Self {
        Self {
            fetcher,
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn entry(&self, name: &str) -> Arc<Entry> {
        let mut map = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(map.entry(name.to_owned()).or_default())
    }

    async fn load(&self, name: &str) -> Result<SecretVersions, AdapterError> {
        let Some(current) = self.fetcher.fetch(name, STAGE_CURRENT).await? else {
            tracing::error!("el secreto no tiene version AWSCURRENT");
            return Err(AdapterError::Permanent);
        };
        let previous = self.fetcher.fetch(name, STAGE_PREVIOUS).await?;
        Ok(SecretVersions { current, previous })
    }
}

impl<F: SecretFetcher> SecretProvider for CachedSecrets<F> {
    async fn get(&self, name: &str) -> Result<SecretVersions, AdapterError> {
        let entry = self.entry(name);
        let mut slot = entry.value.lock().await;
        if let Some((versions, loaded_at)) = slot.as_ref()
            && loaded_at.elapsed() < self.ttl
        {
            return Ok(versions.clone());
        }
        // Un fallo no se cachea: la siguiente `get` vuelve a intentarlo.
        let versions = self.load(name).await?;
        *slot = Some((versions.clone(), Instant::now()));
        Ok(versions)
    }

    /// Descarta la entrada. Una carga en vuelo termina sobre la entrada descartada, asi que
    /// su resultado no se reutiliza.
    fn invalidate(&self, name: &str) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Fake: devuelve el valor configurado, cuenta llamadas y puede tardar o fallar.
    #[derive(Debug, Default)]
    struct Fake {
        calls: AtomicUsize,
        current: StdMutex<String>,
        previous: StdMutex<Option<String>>,
        fail: StdMutex<Option<AdapterError>>,
        delay: Duration,
    }

    impl Fake {
        fn con(current: &str, previous: Option<&str>) -> Arc<Self> {
            Arc::new(Self {
                current: StdMutex::new(current.to_owned()),
                previous: StdMutex::new(previous.map(str::to_owned)),
                ..Self::default()
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl SecretFetcher for Arc<Fake> {
        async fn fetch(&self, _name: &str, stage: &str) -> Result<Option<SecretValue>, AdapterError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            if let Some(e) = *self.fail.lock().unwrap() {
                return Err(e);
            }
            Ok(match stage {
                STAGE_CURRENT => Some(SecretValue::new(self.current.lock().unwrap().clone())),
                _ => self.previous.lock().unwrap().clone().map(SecretValue::new),
            })
        }
    }

    fn provider(f: &Arc<Fake>) -> CachedSecrets<Arc<Fake>> {
        CachedSecrets::new(Arc::clone(f), Duration::from_secs(600))
    }

    #[tokio::test(start_paused = true)]
    async fn devuelve_actual_y_anterior() {
        let f = Fake::con("nuevo", Some("viejo"));
        let v = provider(&f).get("s").await.unwrap();
        assert_eq!(v.current.expose_secret(), "nuevo");
        assert_eq!(v.previous.unwrap().expose_secret(), "viejo");
    }

    #[tokio::test(start_paused = true)]
    async fn sin_version_anterior() {
        let f = Fake::con("nuevo", None);
        let v = provider(&f).get("s").await.unwrap();
        assert!(v.previous.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn la_cache_evita_llamadas_hasta_que_vence_el_ttl() {
        let f = Fake::con("a", None);
        let p = provider(&f);
        p.get("s").await.unwrap();
        let tras_primera = f.calls();
        assert_eq!(tras_primera, 2, "AWSCURRENT y AWSPREVIOUS");

        tokio::time::advance(Duration::from_secs(599)).await;
        p.get("s").await.unwrap();
        assert_eq!(f.calls(), tras_primera);

        *f.current.lock().unwrap() = "b".to_owned();
        tokio::time::advance(Duration::from_secs(1)).await;
        let v = p.get("s").await.unwrap();
        assert_eq!(f.calls(), 2 * tras_primera);
        assert_eq!(v.current.expose_secret(), "b");
    }

    #[tokio::test(start_paused = true)]
    async fn invalidate_fuerza_la_recarga() {
        let f = Fake::con("a", None);
        let p = provider(&f);
        p.get("s").await.unwrap();
        *f.current.lock().unwrap() = "b".to_owned();
        assert_eq!(p.get("s").await.unwrap().current.expose_secret(), "a");
        p.invalidate("s");
        assert_eq!(p.get("s").await.unwrap().current.expose_secret(), "b");
        // Invalidar un nombre desconocido no hace nada.
        p.invalidate("otro");
    }

    #[tokio::test(start_paused = true)]
    async fn los_nombres_tienen_cache_independiente() {
        let f = Fake::con("a", None);
        let p = provider(&f);
        p.get("uno").await.unwrap();
        p.get("dos").await.unwrap();
        assert_eq!(f.calls(), 4);
        p.invalidate("uno");
        p.get("dos").await.unwrap();
        assert_eq!(f.calls(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn single_flight_con_cache_vacia() {
        let f = Arc::new(Fake {
            current: StdMutex::new("a".to_owned()),
            delay: Duration::from_millis(100),
            ..Fake::default()
        });
        let p = Arc::new(provider(&f));
        let mut tareas = tokio::task::JoinSet::new();
        for _ in 0..30 {
            let p = Arc::clone(&p);
            tareas.spawn(async move { p.get("s").await });
        }
        while let Some(r) = tareas.join_next().await {
            assert_eq!(r.unwrap().unwrap().current.expose_secret(), "a");
        }
        assert_eq!(f.calls(), 2, "una sola carga (current + previous)");
    }

    #[tokio::test(start_paused = true)]
    async fn los_errores_no_se_cachean() {
        let f = Fake::con("a", None);
        let p = provider(&f);
        *f.fail.lock().unwrap() = Some(AdapterError::Transient);
        assert_eq!(p.get("s").await.err(), Some(AdapterError::Transient));
        *f.fail.lock().unwrap() = Some(AdapterError::Permanent);
        assert_eq!(p.get("s").await.err(), Some(AdapterError::Permanent));
        *f.fail.lock().unwrap() = None;
        assert_eq!(p.get("s").await.unwrap().current.expose_secret(), "a");
    }

    #[derive(Debug)]
    struct SinCurrent;

    #[allow(clippy::unused_async_trait_impl)]
    impl SecretFetcher for SinCurrent {
        async fn fetch(&self, _: &str, _: &str) -> Result<Option<SecretValue>, AdapterError> {
            Ok(None)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn sin_awscurrent_es_permanente() {
        let p = CachedSecrets::new(SinCurrent, DEFAULT_CACHE_TTL);
        assert_eq!(p.get("s").await.err(), Some(AdapterError::Permanent));
    }

    #[tokio::test(start_paused = true)]
    async fn debug_no_expone_el_valor() {
        let f = Fake::con("super-secreto", Some("viejo-secreto"));
        let v = provider(&f).get("s").await.unwrap();
        let dbg = format!("{v:?}");
        assert!(!dbg.contains("secreto"), "{dbg}");
    }
}
