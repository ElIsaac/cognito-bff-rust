//! `StartLogin` y `CompleteLogin` (§6.1, §6.2).

use std::time::Duration;

use domain::{AuthCode, CodeVerifier, NewSession, Nonce, PendingAuth, PendingId, ReturnTo, SessionId, State};

use crate::ports::{
    AuthorizationRequest, Clock, IdentityProvider, IdpError, PendingAuthStore, Ports, RandomGenerator,
    SessionRepository,
};
use crate::usecases::session::internal;
use crate::{App, AppError, LoginError};

pub enum StartLoginOutcome {
    /// Ya hay sesion valida: `303` a `returnTo` sin pasar por Cognito.
    AlreadyAuthenticated(ReturnTo),
    /// `303` a Cognito y `Set-Cookie: __Host-bff_pending=<pending_id>; Max-Age=<max_age>`.
    Redirect {
        authorization_url: String,
        pending_id: PendingId,
        max_age: Duration,
    },
}

/// Query del callback, tal como llega (una sola decodificacion).
#[derive(Default)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct CompletedLogin {
    /// Va en `__Host-bff_session`; `__Host-bff_pending` se borra.
    pub session_id: SessionId,
    pub max_age: Duration,
    pub return_to: ReturnTo,
}

// La URL de autorizacion lleva `state`, `nonce` y `code_challenge`; el callback lleva
// `code` y `state`. Ninguno debe salir por `{:?}`.
impl std::fmt::Debug for StartLoginOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyAuthenticated(r) => f.debug_tuple("AlreadyAuthenticated").field(r).finish(),
            Self::Redirect {
                pending_id, max_age, ..
            } => f
                .debug_struct("Redirect")
                .field("authorization_url", &"[REDACTED]")
                .field("pending_id", pending_id)
                .field("max_age", max_age)
                .finish(),
        }
    }
}

impl std::fmt::Debug for CallbackParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |v: &Option<String>| v.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("CallbackParams")
            .field("code", &redact(&self.code))
            .field("state", &redact(&self.state))
            .field("error", &self.error)
            .finish()
    }
}

impl<P: Ports> App<P> {
    /// `GET /auth/login?returnTo=...`.
    ///
    /// # Errors
    /// `Internal` si no se pudo guardar el login en curso.
    pub async fn start_login(
        &self,
        session_cookie: Option<&str>,
        return_to: Option<&str>,
    ) -> Result<StartLoginOutcome, AppError> {
        let return_to = ReturnTo::parse_or_default(return_to);
        if session_cookie.is_some() {
            match self.ensure_fresh_session(session_cookie).await {
                Ok(_) => return Ok(StartLoginOutcome::AlreadyAuthenticated(return_to)),
                Err(AppError::Unauthorized) => {}
                Err(e) => return Err(e),
            }
        }

        let rng = self.ports.rng();
        let pending_id = PendingId::from_bytes(rng.bytes32());
        let pending = PendingAuth {
            id_hash: pending_id.hash(),
            state: State::from_bytes(rng.bytes32()),
            nonce: Nonce::from_bytes(rng.bytes32()),
            code_verifier: CodeVerifier::from_bytes(rng.bytes32()),
            return_to,
            created_at: self.ports.clock().now(),
        };
        let ttl = self.cfg.pending.expires_at(pending.created_at);
        self.ports.pending().put(&pending, ttl).await.map_err(internal)?;

        let authorization_url = self.ports.idp().authorization_url(&AuthorizationRequest {
            state: pending.state.clone(),
            nonce: pending.nonce.clone(),
            code_challenge: pending.code_verifier.challenge(),
        });
        Ok(StartLoginOutcome::Redirect {
            authorization_url,
            pending_id,
            max_age: self.cfg.pending.ttl(),
        })
    }

    /// `GET /auth/callback`. El login en curso se consume antes de cualquier otra
    /// comprobacion: un replay del callback siempre falla.
    ///
    /// # Errors
    /// `LoginError` con un codigo de lista blanca; nunca se crea sesion en ese caso.
    pub async fn complete_login(
        &self,
        pending_cookie: Option<&str>,
        params: CallbackParams,
        old_session_cookie: Option<&str>,
    ) -> Result<CompletedLogin, LoginError> {
        let pending_id = pending_cookie
            .and_then(|c| PendingId::parse(c).ok())
            .ok_or(LoginError::MissingPending)?;
        let pending = self
            .ports
            .pending()
            .consume(&pending_id.hash())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "no se pudo consumir el login en curso");
                LoginError::Internal
            })?
            .ok_or(LoginError::InvalidState)?;

        let now = self.ports.clock().now();
        if self.cfg.pending.is_expired(&pending, now) {
            return Err(LoginError::InvalidState);
        }
        if let Some(error) = params.error.as_deref() {
            return Err(LoginError::from_provider(error));
        }
        let state_ok = params
            .state
            .as_deref()
            .and_then(|s| State::parse(s).ok())
            .is_some_and(|s| s.ct_eq(&pending.state));
        if !state_ok {
            return Err(LoginError::InvalidState);
        }
        let code = params
            .code
            .and_then(|c| AuthCode::new(c).ok())
            .ok_or(LoginError::InvalidRequest)?;

        let grant = self
            .ports
            .idp()
            .exchange_code(&code, &pending.code_verifier, &pending.nonce)
            .await
            .map_err(|e| match e {
                IdpError::InvalidGrant | IdpError::TokenRejected => LoginError::ExchangeFailed,
                IdpError::Adapter(_) => LoginError::ProviderUnavailable,
            })?;

        // Fijacion de sesion: la sesion que trajera el navegador se elimina.
        if let Some(old) = old_session_cookie.and_then(|c| SessionId::parse(c).ok())
            && let Err(e) = self.ports.sessions().delete(&old.hash()).await
        {
            tracing::warn!(error = %e, "no se pudo borrar la sesion anterior");
        }

        let now = self.ports.clock().now();
        let session_id = SessionId::from_bytes(self.ports.rng().bytes32());
        let session = NewSession {
            id: session_id.clone(),
            user: grant.user,
            tokens: grant.tokens,
            access_expires_at: now.saturating_add(grant.access_expires_in),
            absolute_expires_at: self.cfg.session.absolute_expiry(now),
            created_at: now,
        }
        .into_session();
        let ttl = self.cfg.session.ttl(&session);
        self.ports.sessions().create(&session, ttl).await.map_err(|e| {
            tracing::error!(error = %e, "no se pudo crear la sesion");
            LoginError::Internal
        })?;

        crate::record_sub(&session.user);
        tracing::info!("login completado");
        Ok(CompletedLogin {
            session_id,
            max_age: self.cfg.session.config().absolute_ttl,
            return_to: pending.return_to,
        })
    }
}
