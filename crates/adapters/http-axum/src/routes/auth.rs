//! `/auth/login`, `/auth/callback`, `/auth/me`, `/auth/logout` y `/auth/ws-ticket`.

use application::ports::{Ports, SecretProvider};
use application::{CallbackParams, StartLoginOutcome};
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use serde_json::json;

use super::{json, see_other};
use crate::cookies::{self, PENDING_COOKIE};
use crate::{ApiError, St};

/// Tope de la query del login y del callback.
const QUERY_MAX: usize = 8 * 1024;

/// Valor de `key` tras una sola decodificacion; `None` si falta, esta repetido o la query
/// es demasiado larga.
fn single(query: Option<&str>, key: &str) -> Option<String> {
    let q = query.filter(|q| q.len() <= QUERY_MAX)?;
    let mut values = url::form_urlencoded::parse(q.as_bytes())
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned());
    match (values.next(), values.next()) {
        (Some(v), None) => Some(v),
        _ => None,
    }
}

/// §6.1.
pub(crate) async fn login<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Result<Response, ApiError> {
    let session = cookies::read(&headers, &st.cfg.session_cookie);
    let return_to = single(query.as_deref(), "returnTo");
    match st
        .app
        .start_login(session.as_deref(), return_to.as_deref())
        .await?
    {
        StartLoginOutcome::AlreadyAuthenticated(r) => Ok(see_other(r.as_str())),
        StartLoginOutcome::Redirect {
            authorization_url,
            pending_id,
            max_age,
        } => {
            let mut resp = see_other(&authorization_url);
            resp.headers_mut().append(
                header::SET_COOKIE,
                cookies::set(PENDING_COOKIE, &pending_id.expose_secret(), max_age),
            );
            Ok(resp)
        }
    }
}

/// §6.2. Siempre termina en `303` y siempre borra la cookie del login en curso.
pub(crate) async fn callback<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let pending = cookies::read(&headers, PENDING_COOKIE);
    let old_session = cookies::read(&headers, &st.cfg.session_cookie);
    let q = query.as_deref();
    let params = CallbackParams {
        code: single(q, "code"),
        state: single(q, "state"),
        error: single(q, "error"),
    };
    let mut resp = match st
        .app
        .complete_login(pending.as_deref(), params, old_session.as_deref())
        .await
    {
        Ok(done) => {
            let mut r = see_other(done.return_to.as_str());
            r.headers_mut().append(
                header::SET_COOKIE,
                cookies::set(
                    &st.cfg.session_cookie,
                    &done.session_id.expose_secret(),
                    done.max_age,
                ),
            );
            r
        }
        Err(e) => {
            tracing::warn!(code = e.code(), "login fallido");
            see_other(&format!("{}?code={}", st.cfg.auth_error_path, e.code()))
        }
    };
    resp.headers_mut()
        .append(header::SET_COOKIE, cookies::clear(PENDING_COOKIE));
    resp
}

/// §6.3.
pub(crate) async fn me<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let cookie = cookies::read(&headers, &st.cfg.session_cookie);
    let u = st.app.current_user(cookie.as_deref()).await?;
    let body = json!({
        "sub": u.sub().as_str(),
        "email": u.email().map(domain::Email::as_str),
        "name": u.name(),
        "groups": u.groups().iter().map(domain::GroupName::as_str).collect::<Vec<_>>(),
        "attributes": u.attributes(),
    });
    Ok(json(StatusCode::OK, &body))
}

/// §6.4. Idempotente; la cookie se borra solo si la sesion ya no existe en el almacen.
pub(crate) async fn logout<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let cookie = cookies::read(&headers, &st.cfg.session_cookie);
    let url = st.app.logout(cookie.as_deref()).await?;
    let mut resp = json(StatusCode::OK, &json!({ "logoutUrl": url }));
    resp.headers_mut()
        .append(header::SET_COOKIE, cookies::clear(&st.cfg.session_cookie));
    Ok(resp)
}

/// §18, paso 1.
pub(crate) async fn ws_ticket<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let cookie = cookies::read(&headers, &st.cfg.session_cookie);
    let t = st.app.issue_ws_ticket(cookie.as_deref()).await?;
    let body = json!({
        "ticket": t.ticket.expose_secret(),
        "expiresIn": t.expires_in.as_secs(),
    });
    Ok(json(StatusCode::OK, &body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_solo_valor() {
        assert_eq!(
            single(Some("returnTo=%2Fa&x=1"), "returnTo").as_deref(),
            Some("/a")
        );
        assert_eq!(single(Some("returnTo=/a&returnTo=/b"), "returnTo"), None);
        assert_eq!(single(Some("x=1"), "returnTo"), None);
        assert_eq!(single(None, "returnTo"), None);
        let largo = format!("returnTo=/{}", "a".repeat(QUERY_MAX));
        assert_eq!(single(Some(&largo), "returnTo"), None);
        // Una sola decodificacion: %252F queda como %2F.
        assert_eq!(single(Some("returnTo=%252F"), "returnTo").as_deref(), Some("%2F"));
    }
}
