use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use application::ports::{AdapterError, LeaseOutcome, SessionRepository, UpdateOutcome};
use domain::{IdHash, Session, Timestamp};

use crate::util::{YieldNow, lock};

#[derive(Debug, Default)]
struct Inner {
    items: HashMap<String, (Session, Timestamp)>,
    failures: VecDeque<AdapterError>,
}

/// Repositorio de sesiones en memoria. Replica las condiciones de `DynamoDB`:
/// `create` con `attribute_not_exists`, `update_if_version` condicional a `version` y
/// `acquire_refresh_lease` con `version = :v AND (sin lease OR lease < :now)`.
///
/// El `ttl` solo se guarda: como en `DynamoDB`, un elemento vencido sigue siendo legible
/// hasta que alguien lo borre.
#[derive(Debug)]
pub struct MemSessions {
    inner: Mutex<Inner>,
    interleave: AtomicBool,
    writes: AtomicUsize,
    lease_attempts: AtomicUsize,
    lease_conflicts: AtomicUsize,
}

impl Default for MemSessions {
    fn default() -> Self {
        Self::new()
    }
}

impl MemSessions {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            interleave: AtomicBool::new(true),
            writes: AtomicUsize::new(0),
            lease_attempts: AtomicUsize::new(0),
            lease_conflicts: AtomicUsize::new(0),
        }
    }

    /// Con `true` (por defecto) `get` y `acquire_refresh_lease` ceden el turno al ejecutor
    /// para que las tareas concurrentes se intercalen entre lectura y escritura.
    pub fn set_interleave(&self, on: bool) {
        self.interleave.store(on, Ordering::Relaxed);
    }

    /// Hace que las proximas `n` operaciones fallen con `err`.
    pub fn inject_failures(&self, err: AdapterError, n: usize) {
        let mut inner = lock(&self.inner);
        inner.failures.extend(std::iter::repeat_n(err, n));
    }

    /// Lectura sincrona para asserts (no cuenta ni cede el turno).
    pub fn snapshot(&self, id: &IdHash) -> Option<Session> {
        lock(&self.inner).items.get(id.as_str()).map(|(s, _)| s.clone())
    }

    /// `ttl` guardado junto a la sesion.
    pub fn ttl_of(&self, id: &IdHash) -> Option<Timestamp> {
        lock(&self.inner).items.get(id.as_str()).map(|(_, t)| *t)
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Escrituras exitosas (create, update, lease, delete de un elemento existente).
    pub fn writes(&self) -> usize {
        self.writes.load(Ordering::Relaxed)
    }

    pub fn lease_attempts(&self) -> usize {
        self.lease_attempts.load(Ordering::Relaxed)
    }

    pub fn lease_conflicts(&self) -> usize {
        self.lease_conflicts.load(Ordering::Relaxed)
    }

    async fn cede(&self) {
        if self.interleave.load(Ordering::Relaxed) {
            YieldNow::default().await;
        }
    }

    fn injected(&self) -> Result<(), AdapterError> {
        match lock(&self.inner).failures.pop_front() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn wrote(&self) {
        self.writes.fetch_add(1, Ordering::Relaxed);
    }
}

impl SessionRepository for MemSessions {
    async fn get(&self, id: &IdHash) -> Result<Option<Session>, AdapterError> {
        self.injected()?;
        let found = self.snapshot(id);
        self.cede().await;
        Ok(found)
    }

    /// Falla con `Permanent` si ya existe (condicion `attribute_not_exists`).
    async fn create(&self, s: &Session, ttl: Timestamp) -> Result<(), AdapterError> {
        self.injected()?;
        let mut inner = lock(&self.inner);
        let key = s.id_hash.as_str().to_owned();
        if inner.items.contains_key(&key) {
            return Err(AdapterError::Permanent);
        }
        inner.items.insert(key, (s.clone(), ttl));
        drop(inner);
        self.wrote();
        Ok(())
    }

    async fn update_if_version(
        &self,
        s: &Session,
        expected: domain::Version,
        ttl: Timestamp,
    ) -> Result<UpdateOutcome, AdapterError> {
        self.injected()?;
        let mut inner = lock(&self.inner);
        match inner.items.get_mut(s.id_hash.as_str()) {
            Some((stored, stored_ttl)) if stored.version == expected => {
                *stored = s.clone();
                *stored_ttl = ttl;
                drop(inner);
                self.wrote();
                Ok(UpdateOutcome::Updated)
            }
            _ => Ok(UpdateOutcome::Conflict),
        }
    }

    async fn acquire_refresh_lease(
        &self,
        id: &IdHash,
        expected: domain::Version,
        now: Timestamp,
        until: Timestamp,
    ) -> Result<LeaseOutcome, AdapterError> {
        self.injected()?;
        self.cede().await;
        self.lease_attempts.fetch_add(1, Ordering::Relaxed);
        let mut inner = lock(&self.inner);
        let outcome = match inner.items.get_mut(id.as_str()) {
            Some((stored, _))
                if stored.version == expected && stored.refresh_lock_until.is_none_or(|l| l < now) =>
            {
                stored.refresh_lock_until = Some(until);
                stored.version = expected.next();
                Some(stored.version)
            }
            _ => None,
        };
        drop(inner);
        if let Some(version) = outcome {
            self.wrote();
            Ok(LeaseOutcome::Acquired { version })
        } else {
            self.lease_conflicts.fetch_add(1, Ordering::Relaxed);
            Ok(LeaseOutcome::Conflict)
        }
    }

    async fn delete(&self, id: &IdHash) -> Result<(), AdapterError> {
        self.injected()?;
        let removed = lock(&self.inner).items.remove(id.as_str()).is_some();
        if removed {
            self.wrote();
        }
        Ok(())
    }
}
