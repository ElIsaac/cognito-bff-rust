//! `/auth/account/*` (decision 48).

use application::AppError;
use application::ports::{Ports, SecretProvider};
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use domain::{DeviceName, Password, TotpCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;

use super::json;
use crate::{ApiError, St, cookies};

/// Tope de los cuerpos JSON de estas rutas.
const JSON_MAX: usize = 4 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VerifyBody {
    code: String,
    #[serde(default)]
    device_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreferenceBody {
    totp: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ChangePasswordBody {
    previous_password: String,
    proposed_password: String,
}

/// Cookie de sesion y cuerpo JSON (`application/json`, acotado).
async fn read_json<T: DeserializeOwned, P: Ports, S: SecretProvider>(
    st: &St<P, S>,
    req: Request,
) -> Result<(Option<String>, T), ApiError> {
    let is_json = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return Err(ApiError::UnsupportedMediaType);
    }
    let cookie = cookies::read(req.headers(), &st.cfg.session_cookie);
    let bytes = axum::body::to_bytes(req.into_body(), JSON_MAX)
        .await
        .map_err(|_| AppError::PayloadTooLarge)?;
    let body = serde_json::from_slice(&bytes).map_err(|_| AppError::BadRequest)?;
    Ok((cookie, body))
}

fn session_cookie<P: Ports, S: SecretProvider>(st: &St<P, S>, req: &Request) -> Option<String> {
    cookies::read(req.headers(), &st.cfg.session_cookie)
}

pub(crate) async fn mfa_status<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    req: Request,
) -> Result<Response, ApiError> {
    let cookie = session_cookie(&st, &req);
    let s = st.app.mfa_status(cookie.as_deref()).await?;
    Ok(json(StatusCode::OK, &json!({ "totp": s.as_str() })))
}

pub(crate) async fn associate<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    req: Request,
) -> Result<Response, ApiError> {
    let cookie = session_cookie(&st, &req);
    let secret = st.app.associate_totp(cookie.as_deref()).await?;
    Ok(json(StatusCode::OK, &json!({ "secret": secret.expose_secret() })))
}

pub(crate) async fn verify<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    req: Request,
) -> Result<Response, ApiError> {
    let (cookie, body): (_, VerifyBody) = read_json(&st, req).await?;
    let code = TotpCode::new(body.code).map_err(|_| AppError::BadRequest)?;
    let device = match body.device_name.as_deref() {
        Some(d) => DeviceName::parse(d).map_err(|_| AppError::BadRequest)?,
        None => None,
    };
    st.app
        .verify_totp(cookie.as_deref(), &code, device.as_ref())
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn preference<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    req: Request,
) -> Result<Response, ApiError> {
    let (cookie, body): (_, PreferenceBody) = read_json(&st, req).await?;
    st.app.set_totp(cookie.as_deref(), body.totp).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn change_password<P: Ports, S: SecretProvider>(
    State(st): State<St<P, S>>,
    req: Request,
) -> Result<Response, ApiError> {
    let (cookie, body): (_, ChangePasswordBody) = read_json(&st, req).await?;
    let previous = Password::new(body.previous_password).map_err(|_| AppError::BadRequest)?;
    let proposed = Password::new(body.proposed_password).map_err(|_| AppError::BadRequest)?;
    st.app
        .change_password(cookie.as_deref(), &previous, &proposed)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
