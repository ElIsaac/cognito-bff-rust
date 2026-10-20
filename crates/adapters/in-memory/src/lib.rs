//! Fakes en memoria de todos los puertos de `application`.
//!
//! Tienen la misma semantica que los adaptadores reales (condiciones de escritura,
//! consumo atomico, PKCE y un solo uso de los codes); los tests de contrato de la Fase 3
//! los comparan. Solo para pruebas.

// Los fakes son sincronos por dentro pero implementan puertos asincronos.
#![allow(clippy::unused_async_trait_impl)]

mod clock;
mod idp;
mod ports;
mod rng;
mod sessions;
mod stores;
mod upstream;
mod util;

pub use clock::{BASE_EPOCH_SECS, TestClock};
pub use idp::FakeIdp;
pub use ports::MemPorts;
pub use rng::TestRng;
pub use sessions::MemSessions;
pub use stores::{MemPending, MemTickets};
pub use upstream::FakeUpstream;
