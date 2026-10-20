use std::collections::HashMap;
use std::sync::Mutex;

use application::ports::{AdapterError, PendingAuthStore, WsTicketStore};
use domain::{IdHash, PendingAuth, Timestamp, WsTicket};

use crate::util::lock;

/// Almacen de elementos de un solo uso: `put` falla si el id ya existe y `consume` lee y
/// borra de forma atomica.
#[derive(Debug)]
struct OnceStore<T> {
    items: Mutex<HashMap<String, (T, Timestamp)>>,
}

impl<T: Clone> OnceStore<T> {
    fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
        }
    }

    fn put(&self, id: &IdHash, item: &T, ttl: Timestamp) -> Result<(), AdapterError> {
        let mut items = lock(&self.items);
        if items.contains_key(id.as_str()) {
            return Err(AdapterError::Permanent);
        }
        items.insert(id.as_str().to_owned(), (item.clone(), ttl));
        Ok(())
    }

    fn consume(&self, id: &IdHash) -> Option<T> {
        lock(&self.items).remove(id.as_str()).map(|(t, _)| t)
    }

    fn snapshot(&self, id: &IdHash) -> Option<T> {
        lock(&self.items).get(id.as_str()).map(|(t, _)| t.clone())
    }

    fn ttl_of(&self, id: &IdHash) -> Option<Timestamp> {
        lock(&self.items).get(id.as_str()).map(|(_, ttl)| *ttl)
    }

    fn keys(&self) -> Vec<String> {
        lock(&self.items).keys().cloned().collect()
    }

    fn len(&self) -> usize {
        lock(&self.items).len()
    }
}

/// `PendingAuthStore` en memoria.
#[derive(Debug)]
pub struct MemPending(OnceStore<PendingAuth>);

impl Default for MemPending {
    fn default() -> Self {
        Self::new()
    }
}

impl MemPending {
    pub fn new() -> Self {
        Self(OnceStore::new())
    }

    /// Lectura sin consumir, para asserts.
    pub fn snapshot(&self, id: &IdHash) -> Option<PendingAuth> {
        self.0.snapshot(id)
    }

    pub fn ttl_of(&self, id: &IdHash) -> Option<Timestamp> {
        self.0.ttl_of(id)
    }

    /// Claves (hash) guardadas.
    pub fn keys(&self) -> Vec<String> {
        self.0.keys()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }
}

impl PendingAuthStore for MemPending {
    async fn put(&self, p: &PendingAuth, ttl: Timestamp) -> Result<(), AdapterError> {
        self.0.put(&p.id_hash, p, ttl)
    }

    async fn consume(&self, id: &IdHash) -> Result<Option<PendingAuth>, AdapterError> {
        Ok(self.0.consume(id))
    }
}

/// `WsTicketStore` en memoria.
#[derive(Debug)]
pub struct MemTickets(OnceStore<WsTicket>);

impl Default for MemTickets {
    fn default() -> Self {
        Self::new()
    }
}

impl MemTickets {
    pub fn new() -> Self {
        Self(OnceStore::new())
    }

    /// Lectura sin consumir, para asserts.
    pub fn snapshot(&self, id: &IdHash) -> Option<WsTicket> {
        self.0.snapshot(id)
    }

    pub fn ttl_of(&self, id: &IdHash) -> Option<Timestamp> {
        self.0.ttl_of(id)
    }

    /// Claves (hash) guardadas.
    pub fn keys(&self) -> Vec<String> {
        self.0.keys()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }
}

impl WsTicketStore for MemTickets {
    async fn put(&self, t: &WsTicket, ttl: Timestamp) -> Result<(), AdapterError> {
        self.0.put(&t.id_hash, t, ttl)
    }

    async fn consume(&self, id: &IdHash) -> Result<Option<WsTicket>, AdapterError> {
        Ok(self.0.consume(id))
    }
}
