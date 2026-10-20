//! URLs de autorizacion y logout.

use std::collections::BTreeMap;

use application::ports::{AuthorizationRequest, IdentityProvider};
use domain::{CodeVerifier, State};

use crate::support::{CLIENT_ID, Env, LOGOUT_URI, REDIRECT_URI, nonce};

fn params(url: &url::Url) -> Vec<(String, String)> {
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// La URL de autorizacion lleva exactamente los 8 parametros OAuth/PKCE esperados (ni
/// mas ni menos, sin duplicados), con `response_type=code` y `S256`, y apunta a
/// `/oauth2/authorize` del dominio configurado: un parametro extra o repetido permitiria
/// degradar PKCE o cambiar el flujo.
#[tokio::test]
async fn authorization_url_exacta() {
    let env = Env::start().await;
    let state = State::from_bytes([5u8; 32]);
    let verifier = CodeVerifier::from_bytes([9u8; 32]);
    let url = env.idp.authorization_url(&AuthorizationRequest {
        state: state.clone(),
        nonce: nonce(),
        code_challenge: verifier.challenge(),
    });
    let url = url::Url::parse(&url).unwrap();

    assert_eq!(url.scheme(), env.mock.base.scheme());
    assert_eq!(url.host_str(), env.mock.base.host_str());
    assert_eq!(url.port(), env.mock.base.port());
    assert_eq!(url.path(), "/oauth2/authorize");
    let p = params(&url);
    assert_eq!(p.len(), 8, "{p:?}");
    let m: BTreeMap<_, _> = p.into_iter().collect();
    assert_eq!(m["response_type"], "code");
    assert_eq!(m["client_id"], CLIENT_ID);
    assert_eq!(m["redirect_uri"], REDIRECT_URI);
    assert_eq!(m["scope"], "openid email profile");
    assert_eq!(m["state"], state.expose_secret());
    assert_eq!(m["nonce"], nonce().expose_secret());
    assert_eq!(m["code_challenge"], verifier.challenge().as_str());
    assert_eq!(m["code_challenge_method"], "S256");
}

/// Los valores se codifican: un `redirect_uri` o `scope` con `&`, `#` o espacios no puede
/// inyectar parametros adicionales.
#[tokio::test]
async fn authorization_url_codifica_los_valores() {
    let env = Env::start_with(|c| {
        c.redirect_uri = "https://app.example.com/cb?x=1&client_id=otro#frag".into();
        c.scopes = "openid email&response_type=token".into();
    })
    .await;
    let url = env.idp.authorization_url(&AuthorizationRequest {
        state: State::from_bytes([5u8; 32]),
        nonce: nonce(),
        code_challenge: CodeVerifier::from_bytes([9u8; 32]).challenge(),
    });
    let url = url::Url::parse(&url).unwrap();
    let p = params(&url);
    assert_eq!(p.len(), 8, "{p:?}");
    assert_eq!(p.iter().filter(|(k, _)| k == "client_id").count(), 1);
    assert_eq!(p.iter().filter(|(k, _)| k == "response_type").count(), 1);
    assert!(url.fragment().is_none());
}

/// `logout_url` apunta a `/logout` del dominio con `client_id` y `logout_uri` (y nada mas).
#[tokio::test]
async fn logout_url() {
    let env = Env::start().await;
    let url = url::Url::parse(&env.idp.logout_url()).unwrap();
    assert_eq!(url.path(), "/logout");
    assert_eq!(url.host_str(), env.mock.base.host_str());
    let m: BTreeMap<_, _> = params(&url).into_iter().collect();
    assert_eq!(m.len(), 2);
    assert_eq!(m["client_id"], CLIENT_ID);
    assert_eq!(m["logout_uri"], LOGOUT_URI);
}
