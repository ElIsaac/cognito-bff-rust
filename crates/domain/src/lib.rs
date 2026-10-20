//! Tipos y reglas puras del BFF.
//!
//! Este crate no conoce AWS, HTTP, OIDC ni Tokio. Todo valor sensible (identificadores de
//! sesion, tokens, `state`, `nonce`, `code_verifier`) va envuelto en tipos cuyo `Debug`
//! imprime `[REDACTED]` y que no implementan `Display`.

mod error;
mod ids;
mod oauth;
mod pending;
mod policy;
mod proxy_path;
mod return_to;
mod session;
mod time;
mod tokens;
mod user;
mod ws_ticket;

pub use error::DomainError;
pub use ids::{IdHash, PendingId, RANDOM_ID_BYTES, SessionId};
pub use oauth::{CodeChallenge, CodeVerifier, Nonce, State};
pub use pending::{PendingAuth, PendingPolicy};
pub use policy::{ExpiryReason, Freshness, SessionPolicy, SessionPolicyConfig};
pub use proxy_path::{PROXY_PATH_MAX_LEN, ProxyPath};
pub use return_to::{RETURN_TO_MAX_LEN, ReturnTo};
pub use session::{NewSession, Session, Version};
pub use time::Timestamp;
pub use tokens::{AccessToken, AuthCode, RefreshToken, TokenSet};
pub use user::{Email, GroupName, Subject, UserInfo};
pub use ws_ticket::{WsTicket, WsTicketId, WsTicketPolicy};
