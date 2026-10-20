use crate::{IdHash, SessionId, Timestamp, TokenSet, UserInfo};

/// Version para escritura condicional (optimistic locking). Empieza en 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(u64);

impl Version {
    pub const INITIAL: Self = Self(1);

    pub const fn from_stored(v: u64) -> Self {
        Self(v)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Sesion recien creada en el callback, antes de guardarse.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub id: SessionId,
    pub user: UserInfo,
    pub tokens: TokenSet,
    pub access_expires_at: Timestamp,
    pub absolute_expires_at: Timestamp,
    pub created_at: Timestamp,
}

impl NewSession {
    /// Forma persistida: version 1 y `last_seen_at = created_at`.
    pub fn into_session(self) -> Session {
        Session {
            id_hash: self.id.hash(),
            version: Version::INITIAL,
            user: self.user,
            tokens: self.tokens,
            access_expires_at: self.access_expires_at,
            absolute_expires_at: self.absolute_expires_at,
            last_seen_at: self.created_at,
            refresh_lock_until: None,
            created_at: self.created_at,
        }
    }
}

/// Sesion persistida. Se identifica por la huella del id, nunca por el id en claro.
#[derive(Debug, Clone)]
pub struct Session {
    pub id_hash: IdHash,
    pub version: Version,
    pub user: UserInfo,
    pub tokens: TokenSet,
    pub access_expires_at: Timestamp,
    pub absolute_expires_at: Timestamp,
    pub last_seen_at: Timestamp,
    pub refresh_lock_until: Option<Timestamp>,
    pub created_at: Timestamp,
}
