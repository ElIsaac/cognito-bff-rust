//! `EnsureFreshSession` y `GetCurrentUser` (§6.3, §6.6).

use std::time::Duration;

use domain::{Freshness, IdHash, Session, SessionId, SessionPolicy, Timestamp, TokenSet, UserInfo};

use crate::ports::{
    AdapterError, Clock, IdentityProvider, IdpError, LeaseOutcome, Ports, RandomGenerator, RefreshGrant,
    SessionRepository, UpdateOutcome,
};
use crate::{App, AppError};

/// Que hacer tras un intento fallido de refresco.
enum Step {
    Done(Box<Session>),
    Retry,
}

impl<P: Ports> App<P> {
    /// Sesion vigente con access token fresco, o `Unauthorized`.
    ///
    /// Con N peticiones simultaneas sobre la misma sesion, exactamente una llama a Cognito:
    /// la que gana el lease en el almacen; el resto espera con backoff y relee.
    ///
    /// # Errors
    /// `Unauthorized` (sin cookie valida, sesion inexistente, expirada o revocada), `Busy`
    /// (lease ajeno tras agotar reintentos) o `Internal`.
    pub async fn ensure_fresh_session(&self, cookie: Option<&str>) -> Result<Session, AppError> {
        let id = cookie
            .and_then(|c| SessionId::parse(c).ok())
            .ok_or(AppError::Unauthorized)?;
        let hash = id.hash();
        let retry = self.cfg.refresh_retry;

        for attempt in 0..retry.max_attempts {
            match self.try_fresh(&hash).await? {
                Step::Done(s) => {
                    crate::record_sub(&s.user);
                    return Ok(*s);
                }
                Step::Retry => self.backoff(attempt).await,
            }
        }
        tracing::warn!("refresh de sesion: reintentos agotados");
        Err(AppError::Busy)
    }

    /// `GET /auth/me`.
    ///
    /// # Errors
    /// Los de `ensure_fresh_session`.
    pub async fn current_user(&self, cookie: Option<&str>) -> Result<UserInfo, AppError> {
        self.ensure_fresh_session(cookie).await.map(|s| s.user)
    }

    async fn try_fresh(&self, hash: &IdHash) -> Result<Step, AppError> {
        let sessions = self.ports.sessions();
        let policy = &self.cfg.session;
        let s = sessions
            .get(hash)
            .await
            .map_err(internal)?
            .ok_or(AppError::Unauthorized)?;
        let now = self.ports.clock().now();

        if let Some(reason) = policy.expiry(&s, now) {
            tracing::info!(?reason, "sesion expirada");
            sessions.delete(hash).await.map_err(internal)?;
            return Err(AppError::Unauthorized);
        }

        match policy.freshness(&s, now) {
            Freshness::Fresh { touch: false } => Ok(Step::Done(Box::new(s))),
            Freshness::Fresh { touch: true } => Ok(Step::Done(Box::new(self.touch(s, now).await))),
            Freshness::NeedsRefresh => self.refresh_with_lease(s, now).await,
        }
    }

    /// Actualiza `last_seen_at`. Un conflicto significa que otra peticion ya escribio la
    /// sesion: no es un error, se devuelve la sesion leida.
    async fn touch(&self, s: Session, now: Timestamp) -> Session {
        let mut touched = s.clone();
        touched.last_seen_at = now;
        touched.version = s.version.next();
        let ttl = self.cfg.session.ttl(&touched);
        match self
            .ports
            .sessions()
            .update_if_version(&touched, s.version, ttl)
            .await
        {
            Ok(UpdateOutcome::Updated) => touched,
            Ok(UpdateOutcome::Conflict) => s,
            Err(e) => {
                tracing::warn!(error = %e, "no se pudo actualizar last_seen_at");
                s
            }
        }
    }

    async fn refresh_with_lease(&self, s: Session, now: Timestamp) -> Result<Step, AppError> {
        if SessionPolicy::lease_held(&s, now) {
            return Ok(Step::Retry);
        }
        let sessions = self.ports.sessions();
        let until = self.cfg.session.lease_until(now);
        let leased = match sessions
            .acquire_refresh_lease(&s.id_hash, s.version, now, until)
            .await
        {
            Ok(LeaseOutcome::Acquired { version }) => version,
            Ok(LeaseOutcome::Conflict) | Err(AdapterError::Transient) => return Ok(Step::Retry),
            Err(e) => return Err(internal(e)),
        };

        match self.ports.idp().refresh(&s.tokens.refresh).await {
            // Un ID token de otro usuario es tan invalido como uno con mala firma.
            Ok(grant) if grant.user.as_ref().is_some_and(|u| u.sub() != s.user.sub()) => {
                tracing::warn!("refresh con un sub distinto al de la sesion");
                self.reject_refresh(&s, leased).await
            }
            Ok(grant) => self.store_refreshed(s, leased, grant).await,
            Err(IdpError::InvalidGrant | IdpError::TokenRejected) => self.reject_refresh(&s, leased).await,
            Err(IdpError::Adapter(e)) => {
                tracing::warn!(error = %e, "refresh fallido: se libera el lease");
                self.release_lease(&s, leased).await;
                // Con el access token aun vigente se sirve tal cual. Si ya vencio se responde
                // 503 de inmediato: reintentar aqui multiplicaria las llamadas a un
                // proveedor caido.
                let now = self.ports.clock().now();
                if s.access_expires_at > now {
                    Ok(Step::Done(Box::new(s)))
                } else {
                    Err(AppError::Busy)
                }
            }
        }
    }

    async fn reject_refresh(&self, s: &Session, leased: domain::Version) -> Result<Step, AppError> {
        let sessions = self.ports.sessions();
        // Si nuestro lease caduco durante una llamada lenta, otra invocacion pudo
        // refrescar (y rotar) con el mismo token: eso no es una revocacion.
        let current = sessions.get(&s.id_hash).await.map_err(internal)?;
        if current.is_some_and(|c| c.version != leased) {
            tracing::warn!("refresh rechazado tras perder el lease: se reintenta");
            return Ok(Step::Retry);
        }
        tracing::info!("refresh rechazado por el proveedor: se cierra la sesion");
        sessions.delete(&s.id_hash).await.map_err(internal)?;
        Err(AppError::Unauthorized)
    }

    async fn store_refreshed(
        &self,
        s: Session,
        leased: domain::Version,
        grant: RefreshGrant,
    ) -> Result<Step, AppError> {
        let now = self.ports.clock().now();
        let mut fresh = s.clone();
        fresh.tokens = TokenSet {
            access: grant.access,
            refresh: grant.refresh.unwrap_or(s.tokens.refresh),
        };
        fresh.access_expires_at = now.saturating_add(grant.access_expires_in);
        if let Some(user) = grant.user {
            fresh.user = user;
        }
        fresh.last_seen_at = now;
        fresh.refresh_lock_until = None;
        fresh.version = leased.next();
        let ttl = self.cfg.session.ttl(&fresh);

        match self.ports.sessions().update_if_version(&fresh, leased, ttl).await {
            Ok(UpdateOutcome::Updated) => Ok(Step::Done(Box::new(fresh))),
            // La sesion se borro (logout) o perdimos el lease: el timeout del IdP debe ser
            // menor que el lease (decision 42), asi que lo segundo no deberia ocurrir.
            Ok(UpdateOutcome::Conflict) => {
                match self
                    .ports
                    .sessions()
                    .get(&fresh.id_hash)
                    .await
                    .map_err(internal)?
                {
                    None => Err(AppError::Unauthorized),
                    Some(_) => Ok(Step::Retry),
                }
            }
            Err(e) => Err(internal(e)),
        }
    }

    async fn release_lease(&self, s: &Session, leased: domain::Version) {
        let mut released = s.clone();
        released.refresh_lock_until = None;
        released.version = leased.next();
        let ttl = self.cfg.session.ttl(&released);
        if let Err(e) = self
            .ports
            .sessions()
            .update_if_version(&released, leased, ttl)
            .await
        {
            // El lease caduca solo; otra invocacion lo tomara.
            tracing::warn!(error = %e, "no se pudo liberar el lease");
        }
    }

    /// Espera `delay/2 + U[0, delay/2)` (jitter "igual").
    async fn backoff(&self, attempt: u32) {
        let delay = self.cfg.refresh_retry.delay(attempt);
        let half = u64::try_from(delay.as_millis() / 2).unwrap_or(u64::MAX).max(1);
        let jitter = self.ports.rng().below(half);
        self.ports
            .clock()
            .sleep(Duration::from_millis(half + jitter))
            .await;
    }
}

pub(crate) fn internal(e: AdapterError) -> AppError {
    tracing::error!(error = %e, "fallo de adaptador");
    AppError::Internal
}
