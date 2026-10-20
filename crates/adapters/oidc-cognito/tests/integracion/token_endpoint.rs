//! Errores y casos limite del token endpoint, rotacion del secreto y revocacion.

use std::time::Duration;

use application::ports::{AdapterError, IdentityProvider, IdpError};
use domain::RefreshToken;
use serde_json::json;

use crate::support::{ACCESS_TOKEN, CLIENT_SECRET, Env, Mock, REFRESH_TOKEN, Reply, key_a};

const SECRETO_ROTADO: &str = "client-secret-rotado-0002";

fn transient() -> IdpError {
    IdpError::Adapter(AdapterError::Transient)
}

fn permanent() -> IdpError {
    IdpError::Adapter(AdapterError::Permanent)
}

/// Code ya usado/caducado o refresh revocado: `invalid_grant` -> `InvalidGrant` (el BFF
/// borra la sesion, no reintenta).
#[tokio::test]
async fn invalid_grant() {
    let env = Env::start().await;
    env.mock.push_token(Reply::error(400, "invalid_grant"));
    assert_eq!(
        env.exchange_programmed().await.unwrap_err(),
        IdpError::InvalidGrant
    );
    assert_eq!(env.mock.token_requests().len(), 1, "sin reintento");
    assert_eq!(env.secrets.invalidations(), 0);
}

/// Rotacion del secreto: el secreto cacheado es el viejo, Cognito responde
/// `invalid_client`; se invalida UNA vez, se recarga y el reintento (con el secreto nuevo)
/// funciona.
#[tokio::test]
async fn invalid_client_rota_el_secreto_y_reintenta_una_vez() {
    let env = Env::start().await;
    env.mock.set_expected_secret(Some(SECRETO_ROTADO));
    env.secrets.rotate_on_invalidate(SECRETO_ROTADO);
    let id = key_a().token(&env.claims());
    let grant = env.exchange(&id).await.unwrap();
    assert_eq!(grant.tokens.access.expose_secret(), ACCESS_TOKEN);

    assert_eq!(env.secrets.invalidations(), 1);
    assert_eq!(env.secrets.gets(), 2);
    let reqs = env.mock.token_requests();
    assert_eq!(reqs.len(), 2);
    assert_eq!(
        reqs[0].authorization.as_deref(),
        Some(Mock::basic(CLIENT_SECRET).as_str())
    );
    assert_eq!(
        reqs[1].authorization.as_deref(),
        Some(Mock::basic(SECRETO_ROTADO).as_str())
    );
}

/// `invalid_client` declarado en el cuerpo (400 `{"error":"invalid_client"}`, como
/// responde Cognito) tambien dispara la recarga y el reintento.
#[tokio::test]
async fn invalid_client_en_cuerpo_reintenta() {
    let env = Env::start().await;
    env.mock.set_expected_secret(None);
    env.mock.push_token(Reply::error(400, "invalid_client"));
    let id = key_a().token(&env.claims());
    env.mock.push_token(Reply::tokens(Some(&id), Some(REFRESH_TOKEN)));
    assert!(env.exchange_programmed().await.is_ok());
    assert_eq!(env.secrets.invalidations(), 1);
    assert_eq!(env.mock.token_requests().len(), 2);
}

/// Secreto mal configurado: `invalid_client` persistente -> `Adapter(Permanent)` tras
/// exactamente un reintento (2 peticiones, 1 invalidacion), sin bucle ni tercer intento.
#[tokio::test]
async fn invalid_client_persistente_es_permanente_sin_tercer_intento() {
    let env = Env::start().await;
    env.secrets.set_current("secreto-equivocado");
    assert_eq!(env.exchange_programmed().await.unwrap_err(), permanent());
    assert_eq!(env.mock.token_requests().len(), 2);
    assert_eq!(env.secrets.invalidations(), 1);
    assert_eq!(env.secrets.gets(), 2);
}

/// Igual que el anterior pero con `invalid_client` programado repetidamente (Cognito que
/// rechaza aun con el secreto recargado) y respuestas 401 sin cuerpo.
#[tokio::test]
async fn invalid_client_401_sin_cuerpo_tambien_cuenta() {
    let env = Env::start().await;
    env.mock.set_expected_secret(None);
    env.mock.push_token(Reply::raw(401, ""));
    env.mock.push_token(Reply::raw(401, ""));
    env.mock.push_token(Reply::tokens(None, None));
    assert_eq!(env.exchange_programmed().await.unwrap_err(), permanent());
    assert_eq!(env.mock.token_requests().len(), 2);
}

/// Cognito caido o limitando: 500/502/503/504/429 son transitorios (se puede reintentar
/// mas tarde), sin invalidar el secreto.
#[tokio::test]
async fn errores_5xx_y_429_son_transitorios() {
    let env = Env::start().await;
    for status in [500, 502, 503, 504, 429] {
        env.mock.push_token(Reply::raw(status, "<html>error</html>"));
        assert_eq!(
            env.exchange_programmed().await.unwrap_err(),
            transient(),
            "{status}"
        );
    }
    assert_eq!(env.secrets.invalidations(), 0);
}

/// 5xx con cuerpo JSON `invalid_grant` sigue la clasificacion por `error` (un 400 con
/// `invalid_grant` no se confunde con transitorio) y un 4xx inesperado es permanente.
#[tokio::test]
async fn otros_4xx_son_permanentes() {
    let env = Env::start().await;
    for (status, error) in [
        (400, "unsupported_grant_type"),
        (400, "invalid_request"),
        (403, "forbidden"),
    ] {
        env.mock.push_token(Reply::error(status, error));
        assert_eq!(
            env.exchange_programmed().await.unwrap_err(),
            permanent(),
            "{status} {error}"
        );
    }
    env.mock.push_token(Reply::raw(302, ""));
    assert_eq!(env.exchange_programmed().await.unwrap_err(), permanent());
}

/// Cognito lento (mas alla de `http_timeout`): el BFF no espera indefinidamente ->
/// `Adapter(Transient)`.
#[tokio::test]
async fn respuesta_lenta_excede_el_timeout() {
    let env = Env::start_with(|c| c.http_timeout = Duration::from_millis(300)).await;
    env.mock
        .push_token(Reply::tokens(None, None).delayed(Duration::from_secs(3)));
    let t = std::time::Instant::now();
    assert_eq!(env.exchange_programmed().await.unwrap_err(), transient());
    assert!(t.elapsed() < Duration::from_secs(2), "tardo {:?}", t.elapsed());
}

/// Un fallo del `SecretProvider` (Secrets Manager caido) se propaga como error del
/// adaptador sin llamar a Cognito.
#[tokio::test]
async fn fallo_del_secret_provider_no_llama_a_cognito() {
    let env = Env::start().await;
    env.secrets.fail_with(AdapterError::Transient);
    assert_eq!(env.exchange_programmed().await.unwrap_err(), transient());
    assert!(env.mock.token_requests().is_empty());
}

/// `token_type` distinto de Bearer (p. ej. `mac`, `DPoP`) -> `TokenRejected`; `bearer` en
/// minusculas es valido.
#[tokio::test]
async fn token_type_distinto_de_bearer() {
    let env = Env::start().await;
    let id = key_a().token(&env.claims());
    for tt in ["mac", "DPoP", "", "Bearer2"] {
        env.mock.push_token(Reply::json(
            200,
            &json!({"access_token": ACCESS_TOKEN, "id_token": id, "refresh_token": REFRESH_TOKEN,
                    "expires_in": 3600, "token_type": tt}),
        ));
        assert_eq!(
            env.exchange_programmed().await.unwrap_err(),
            IdpError::TokenRejected,
            "{tt:?}"
        );
    }
    env.mock.push_token(Reply::json(
        200,
        &json!({"access_token": ACCESS_TOKEN, "id_token": id, "refresh_token": REFRESH_TOKEN,
                "expires_in": 3600, "token_type": "bearer"}),
    ));
    assert!(env.exchange_programmed().await.is_ok());
}

/// Canje sin `id_token` (p. ej. falto el scope `openid`): no hay identidad verificable ->
/// `TokenRejected`, nunca una sesion sin usuario.
#[tokio::test]
async fn canje_sin_id_token() {
    let env = Env::start().await;
    env.mock.push_token(Reply::tokens(None, Some(REFRESH_TOKEN)));
    assert_eq!(
        env.exchange_programmed().await.unwrap_err(),
        IdpError::TokenRejected
    );
}

/// Canje sin `refresh_token`: la sesion no podria renovarse -> `TokenRejected`.
#[tokio::test]
async fn canje_sin_refresh_token() {
    let env = Env::start().await;
    let id = key_a().token(&env.claims());
    env.mock.push_token(Reply::tokens(Some(&id), None));
    assert_eq!(
        env.exchange_programmed().await.unwrap_err(),
        IdpError::TokenRejected
    );
}

/// Tokens con caracteres no admitidos (espacios, saltos de linea, vacios) en la respuesta
/// se rechazan antes de llegar a la sesion (inyeccion de cabeceras al reenviar el bearer).
#[tokio::test]
async fn tokens_con_caracteres_invalidos() {
    let env = Env::start().await;
    let id = key_a().token(&env.claims());
    for malo in ["", "con espacio", "linea\r\nX-Inyectado: 1"] {
        env.mock.push_token(Reply::json(
            200,
            &json!({"access_token": malo, "id_token": id, "refresh_token": REFRESH_TOKEN,
                    "expires_in": 3600, "token_type": "Bearer"}),
        ));
        assert_eq!(
            env.exchange_programmed().await.unwrap_err(),
            IdpError::TokenRejected,
            "access {malo:?}"
        );
        env.mock.push_token(Reply::json(
            200,
            &json!({"access_token": ACCESS_TOKEN, "id_token": id, "refresh_token": malo,
                    "expires_in": 3600, "token_type": "Bearer"}),
        ));
        assert_eq!(
            env.exchange_programmed().await.unwrap_err(),
            IdpError::TokenRejected,
            "refresh {malo:?}"
        );
    }
}

/// 200 con cuerpo que no es JSON o al que le faltan campos obligatorios (`access_token`,
/// `expires_in`): error permanente, no un panico.
#[tokio::test]
async fn respuesta_200_malformada() {
    let env = Env::start().await;
    for body in [
        "no es json",
        "{}",
        "[]",
        r#"{"access_token":"x"}"#,
        r#"{"access_token":"x","expires_in":-1,"token_type":"Bearer"}"#,
    ] {
        env.mock.push_token(Reply::raw(200, body));
        assert_eq!(
            env.exchange_programmed().await.unwrap_err(),
            permanent(),
            "{body}"
        );
    }
}

/// `revoke` envia `token=<refresh>` (y solo eso) con Basic auth al endpoint de revoke.
#[tokio::test]
async fn revoke_envia_el_token_con_basic_auth() {
    let env = Env::start().await;
    env.mock.push_revoke(Reply::raw(200, ""));
    let refresh = RefreshToken::new(REFRESH_TOKEN.into()).unwrap();
    env.idp.revoke(&refresh).await.unwrap();

    let reqs = env.mock.requests("/oauth2/revoke");
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        reqs[0].authorization.as_deref(),
        Some(Mock::basic(CLIENT_SECRET).as_str())
    );
    assert_eq!(reqs[0].form, [("token".to_owned(), REFRESH_TOKEN.to_owned())]);
    assert!(env.mock.token_requests().is_empty());
}

/// Errores de revoke: Cognito caido -> transitorio; `invalid_client` con secreto rotado
/// se reintenta una vez.
#[tokio::test]
async fn revoke_errores_y_rotacion_del_secreto() {
    let env = Env::start().await;
    let refresh = RefreshToken::new(REFRESH_TOKEN.into()).unwrap();
    env.mock.push_revoke(Reply::raw(503, ""));
    assert_eq!(env.idp.revoke(&refresh).await.unwrap_err(), transient());

    env.mock.set_expected_secret(Some(SECRETO_ROTADO));
    env.secrets.rotate_on_invalidate(SECRETO_ROTADO);
    env.mock.push_revoke(Reply::raw(200, ""));
    env.idp.revoke(&refresh).await.unwrap();
    assert_eq!(env.secrets.invalidations(), 1);
    assert_eq!(env.mock.requests("/oauth2/revoke").len(), 3);
}
