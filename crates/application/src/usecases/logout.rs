//! `Logout` (§6.4).

use domain::SessionId;

use crate::ports::{IdentityProvider, Ports, SessionRepository};
use crate::usecases::session::internal;
use crate::{App, AppError};

impl<P: Ports> App<P> {
    /// `POST /auth/logout` (CSRF lo valida la capa HTTP). Idempotente: sin sesion devuelve
    /// igual la URL de logout de Cognito.
    ///
    /// # Errors
    /// `Internal` si la sesion existe y no se pudo borrar (la cookie no debe darse por
    /// cerrada si la sesion sigue en el almacen).
    pub async fn logout(&self, cookie: Option<&str>) -> Result<String, AppError> {
        if let Some(id) = cookie.and_then(|c| SessionId::parse(c).ok()) {
            let hash = id.hash();
            let sessions = self.ports.sessions();
            if let Some(s) = sessions.get(&hash).await.map_err(internal)? {
                if let Err(e) = self.ports.idp().revoke(&s.tokens.refresh).await {
                    tracing::warn!(error = %e, "no se pudo revocar el refresh token");
                }
                sessions.delete(&hash).await.map_err(internal)?;
                tracing::info!("logout");
            }
        }
        Ok(self.ports.idp().logout_url())
    }
}
