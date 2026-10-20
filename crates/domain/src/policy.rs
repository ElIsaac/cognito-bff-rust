use std::time::Duration;

use crate::{DomainError, Session, Timestamp};

/// Parametros de vida de sesion (variables `SESSION_*`, `ACCESS_REFRESH_THRESHOLD_SECS`,
/// `REFRESH_LEASE_SECS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicyConfig {
    /// Vida absoluta desde el login. Debe ser ≤ validez del refresh token en Cognito.
    pub absolute_ttl: Duration,
    /// Inactividad maxima (deslizante).
    pub idle_ttl: Duration,
    /// Se refresca si al access token le queda esto o menos.
    pub refresh_threshold: Duration,
    /// Duracion del lease de refresh.
    pub refresh_lease: Duration,
    /// `last_seen_at` se escribe como mucho una vez por este intervalo.
    pub touch_interval: Duration,
}

impl Default for SessionPolicyConfig {
    fn default() -> Self {
        Self {
            absolute_ttl: Duration::from_hours(30 * 24),
            idle_ttl: Duration::from_hours(12),
            refresh_threshold: Duration::from_secs(60),
            refresh_lease: Duration::from_secs(10),
            touch_interval: Duration::from_mins(5),
        }
    }
}

/// Por que una sesion ya no vale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryReason {
    Absolute,
    Idle,
}

/// Estado del access token de una sesion vigente.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Sirve tal cual; `touch` indica si toca actualizar `last_seen_at`.
    Fresh { touch: bool },
    /// Hay que refrescar antes de usarlo.
    NeedsRefresh,
}

/// Reglas puras de expiracion, refresco y lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy(SessionPolicyConfig);

const MAX_LEASE: Duration = Duration::from_secs(60);

impl SessionPolicy {
    /// # Errors
    /// `DomainError::InvalidPolicy` si alguna duracion es cero o las relaciones entre ellas
    /// no tienen sentido (inactividad > absoluta, toque ≥ inactividad, lease > 60 s).
    pub fn new(c: SessionPolicyConfig) -> Result<Self, DomainError> {
        let zero = Duration::ZERO;
        if [c.absolute_ttl, c.idle_ttl, c.refresh_lease, c.touch_interval].contains(&zero) {
            return Err(DomainError::InvalidPolicy("duracion en cero"));
        }
        if c.idle_ttl > c.absolute_ttl {
            return Err(DomainError::InvalidPolicy("inactividad mayor que vida absoluta"));
        }
        if c.touch_interval >= c.idle_ttl {
            return Err(DomainError::InvalidPolicy(
                "intervalo de last_seen_at >= inactividad",
            ));
        }
        if c.refresh_lease > MAX_LEASE {
            return Err(DomainError::InvalidPolicy("lease de refresh mayor que 60 s"));
        }
        Ok(Self(c))
    }

    pub fn config(&self) -> &SessionPolicyConfig {
        &self.0
    }

    pub fn absolute_expiry(&self, created_at: Timestamp) -> Timestamp {
        created_at.saturating_add(self.0.absolute_ttl)
    }

    fn idle_expiry(&self, s: &Session) -> Timestamp {
        s.last_seen_at.saturating_add(self.0.idle_ttl)
    }

    /// Valor del atributo `ttl` del almacen: lo que venza primero.
    pub fn ttl(&self, s: &Session) -> Timestamp {
        s.absolute_expires_at.min(self.idle_expiry(s))
    }

    /// `None` si la sesion sigue vigente en `now`. Se comprueba siempre en codigo: el
    /// borrado por TTL del almacen es diferido y no es una garantia.
    pub fn expiry(&self, s: &Session, now: Timestamp) -> Option<ExpiryReason> {
        if now >= s.absolute_expires_at {
            Some(ExpiryReason::Absolute)
        } else if now >= self.idle_expiry(s) {
            Some(ExpiryReason::Idle)
        } else {
            None
        }
    }

    /// Requiere que la sesion este vigente (`expiry` == `None`).
    pub fn freshness(&self, s: &Session, now: Timestamp) -> Freshness {
        if s.access_expires_at.saturating_since(now) > self.0.refresh_threshold {
            Freshness::Fresh {
                touch: now.saturating_since(s.last_seen_at) >= self.0.touch_interval,
            }
        } else {
            Freshness::NeedsRefresh
        }
    }

    pub fn lease_until(&self, now: Timestamp) -> Timestamp {
        now.saturating_add(self.0.refresh_lease)
    }

    /// Hay otra invocacion refrescando y su lease no ha caducado.
    pub fn lease_held(s: &Session, now: Timestamp) -> bool {
        s.refresh_lock_until.is_some_and(|until| until > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessToken, NewSession, RefreshToken, SessionId, Subject, TokenSet, UserInfo};

    fn policy() -> SessionPolicy {
        SessionPolicy::new(SessionPolicyConfig::default()).unwrap()
    }

    fn session(created: u64, access_exp: u64) -> Session {
        let p = policy();
        NewSession {
            id: SessionId::from_bytes([1; 32]),
            user: UserInfo::new(Subject::new("s".into()).unwrap(), None, None, vec![]),
            tokens: TokenSet {
                access: AccessToken::new("a".into()).unwrap(),
                refresh: RefreshToken::new("r".into()).unwrap(),
            },
            access_expires_at: Timestamp::from_secs(access_exp),
            absolute_expires_at: p.absolute_expiry(Timestamp::from_secs(created)),
            created_at: Timestamp::from_secs(created),
        }
        .into_session()
    }

    const T0: u64 = 1_000_000;
    const H: u64 = 3600;

    #[test]
    fn vigente_inactiva_y_absoluta() {
        let p = policy();
        let mut s = session(T0, T0 + 900);
        assert_eq!(p.expiry(&s, Timestamp::from_secs(T0 + 11 * H)), None);
        assert_eq!(
            p.expiry(&s, Timestamp::from_secs(T0 + 12 * H)),
            Some(ExpiryReason::Idle)
        );
        s.last_seen_at = Timestamp::from_secs(T0 + 30 * 24 * H - 60);
        assert_eq!(
            p.expiry(&s, Timestamp::from_secs(T0 + 30 * 24 * H)),
            Some(ExpiryReason::Absolute)
        );
    }

    #[test]
    fn ttl_es_el_minimo() {
        let p = policy();
        let mut s = session(T0, T0 + 900);
        assert_eq!(p.ttl(&s), Timestamp::from_secs(T0 + 12 * H));
        s.last_seen_at = Timestamp::from_secs(T0 + 30 * 24 * H - H);
        assert_eq!(p.ttl(&s), s.absolute_expires_at);
    }

    #[test]
    fn umbral_de_refresh_estricto() {
        let p = policy();
        let s = session(T0, T0 + 900);
        assert_eq!(
            p.freshness(&s, Timestamp::from_secs(T0 + 839)),
            Freshness::Fresh { touch: true }
        );
        assert_eq!(
            p.freshness(&s, Timestamp::from_secs(T0 + 840)),
            Freshness::NeedsRefresh
        );
        assert_eq!(
            p.freshness(&s, Timestamp::from_secs(T0 + 5000)),
            Freshness::NeedsRefresh
        );
    }

    #[test]
    fn touch_cada_cinco_minutos() {
        let p = policy();
        let s = session(T0, T0 + 900);
        assert_eq!(
            p.freshness(&s, Timestamp::from_secs(T0 + 299)),
            Freshness::Fresh { touch: false }
        );
        assert_eq!(
            p.freshness(&s, Timestamp::from_secs(T0 + 300)),
            Freshness::Fresh { touch: true }
        );
    }

    #[test]
    fn lease() {
        let p = policy();
        let mut s = session(T0, T0);
        let now = Timestamp::from_secs(T0);
        assert!(!SessionPolicy::lease_held(&s, now));
        s.refresh_lock_until = Some(p.lease_until(now));
        assert!(SessionPolicy::lease_held(&s, Timestamp::from_secs(T0 + 9)));
        assert!(!SessionPolicy::lease_held(&s, Timestamp::from_secs(T0 + 10)));
    }

    #[test]
    fn configuraciones_invalidas() {
        let d = SessionPolicyConfig::default();
        let casos = [
            SessionPolicyConfig {
                absolute_ttl: Duration::ZERO,
                ..d
            },
            SessionPolicyConfig {
                idle_ttl: Duration::from_secs(31 * 24 * H),
                ..d
            },
            SessionPolicyConfig {
                touch_interval: d.idle_ttl,
                ..d
            },
            SessionPolicyConfig {
                refresh_lease: Duration::from_secs(61),
                ..d
            },
        ];
        for c in casos {
            assert!(SessionPolicy::new(c).is_err(), "{c:?}");
        }
    }
}
