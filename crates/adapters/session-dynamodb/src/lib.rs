//! Almacenes de sesion, login en curso y boleto de WebSocket sobre UNA tabla de `DynamoDB`
//! (clave `pk` de tipo S, TTL en `ttl`). Ver el modelo de datos del plan (seccion 5).
//!
//! Semantica identica a la de los fakes de `in-memory`:
//! - `create`/`put`: `attribute_not_exists(pk)`; el duplicado es `Permanent`.
//! - `get`: lectura fuertemente consistente.
//! - `update_if_version`: reemplazo condicional a la version.
//! - `acquire_refresh_lease`: condicion atomica sobre version y lease.
//! - `consume`: `DeleteItem` con `ReturnValues = ALL_OLD`.
//!
//! Los logs nunca incluyen valores de atributos: solo la operacion y el codigo de error.

mod codec;
mod error;
mod sessions;
mod stores;

pub use sessions::DynamoSessions;
pub use stores::{DynamoPending, DynamoTickets};

/// Prefijos de la clave de particion.
pub(crate) const SESSION_PREFIX: &str = "SESSION#";
pub(crate) const PENDING_PREFIX: &str = "PENDING#";
pub(crate) const WSTICKET_PREFIX: &str = "WSTICKET#";
