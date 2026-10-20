//! Refresh del token: sin nonce, con y sin rotacion.

use application::ports::{IdentityProvider, IdpError};
use domain::RefreshToken;
use serde_json::json;

use crate::support::{
    ACCESS_TOKEN, CLIENT_SECRET, Env, Mock, NEW_REFRESH_TOKEN, REFRESH_TOKEN, Reply, key_a,
};

fn refresh_token() -> RefreshToken {
    RefreshToken::new(REFRESH_TOKEN.into()).unwrap()
}

/// En un refresh Cognito no incluye `nonce` en el ID token: debe aceptarse (rechazarlo
/// dejaria todas las sesiones sin renovar). El form lleva `grant_type=refresh_token` y el
/// refresh token, con Basic auth.
#[tokio::test]
async fn refresh_sin_nonce_se_acepta_y_actualiza_el_usuario() {
    let env = Env::start().await;
    let mut c = env.claims();
    c.as_object_mut().unwrap().remove("nonce");
    c["cognito:groups"] = json!(["nuevo-grupo"]);
    env.mock.push_token(Reply::tokens(Some(&key_a().token(&c)), None));
    let grant = env.idp.refresh(&refresh_token()).await.unwrap();

    assert_eq!(grant.access.expose_secret(), ACCESS_TOKEN);
    let user = grant.user.expect("ID token validado");
    assert_eq!(user.groups()[0].as_str(), "nuevo-grupo");
    let r = &env.mock.token_requests()[0];
    assert_eq!(r.field("grant_type"), Some("refresh_token"));
    assert_eq!(r.field("refresh_token"), Some(REFRESH_TOKEN));
    assert_eq!(r.form.len(), 2);
    assert_eq!(
        r.authorization.as_deref(),
        Some(Mock::basic(CLIENT_SECRET).as_str())
    );
}

/// Si Cognito rota el refresh token, la respuesta trae uno nuevo y se devuelve `Some`
/// (el BFF debe guardarlo, o la siguiente renovacion usaria uno invalido).
#[tokio::test]
async fn refresh_con_rotacion_devuelve_el_nuevo_token() {
    let env = Env::start().await;
    env.mock.push_token(Reply::tokens(None, Some(NEW_REFRESH_TOKEN)));
    let grant = env.idp.refresh(&refresh_token()).await.unwrap();
    assert_eq!(grant.refresh.unwrap().expose_secret(), NEW_REFRESH_TOKEN);
    assert!(grant.user.is_none(), "sin id_token no hay usuario nuevo");
}

/// Sin rotacion (caso normal de Cognito) el refresh token se conserva: `None`.
#[tokio::test]
async fn refresh_sin_rotacion_devuelve_none() {
    let env = Env::start().await;
    let mut c = env.claims();
    c.as_object_mut().unwrap().remove("nonce");
    env.mock.push_token(Reply::tokens(Some(&key_a().token(&c)), None));
    let grant = env.idp.refresh(&refresh_token()).await.unwrap();
    assert!(grant.refresh.is_none());
}

/// Refresh token revocado o caducado: `invalid_grant` -> `InvalidGrant` (cierra la sesion).
#[tokio::test]
async fn refresh_invalid_grant() {
    let env = Env::start().await;
    env.mock.push_token(Reply::error(400, "invalid_grant"));
    assert_eq!(
        env.idp.refresh(&refresh_token()).await.unwrap_err(),
        IdpError::InvalidGrant
    );
}

/// El ID token de un refresh se valida igual de estricto (sin nonce, pero con firma, `iss`,
/// `aud`, `exp`, `token_use`): un ID token falsificado en un refresh se rechaza.
#[tokio::test]
async fn refresh_con_id_token_falsificado_se_rechaza() {
    let env = Env::start().await;
    let mut c = env.claims();
    c.as_object_mut().unwrap().remove("nonce");
    let forged = crate::support::key_attacker().token(&c);
    env.mock.push_token(Reply::tokens(Some(&forged), None));
    assert_eq!(
        env.idp.refresh(&refresh_token()).await.unwrap_err(),
        IdpError::TokenRejected
    );

    c["aud"] = json!("otro");
    env.mock.push_token(Reply::tokens(Some(&key_a().token(&c)), None));
    assert_eq!(
        env.idp.refresh(&refresh_token()).await.unwrap_err(),
        IdpError::TokenRejected
    );
}

/// En un refresh con `token_type` distinto de Bearer tambien se rechaza.
#[tokio::test]
async fn refresh_token_type_invalido() {
    let env = Env::start().await;
    env.mock.push_token(Reply::json(
        200,
        &json!({"access_token": ACCESS_TOKEN, "expires_in": 3600, "token_type": "mac"}),
    ));
    assert_eq!(
        env.idp.refresh(&refresh_token()).await.unwrap_err(),
        IdpError::TokenRejected
    );
}
