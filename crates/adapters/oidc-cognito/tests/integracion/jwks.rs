//! Cache del JWKS: descargas por `kid` desconocido, limite de refetch y rotacion.

use std::sync::Arc;
use std::time::Duration;

use application::ports::{AdapterError, IdentityProvider, IdpError};
use oidc_cognito::CognitoIdp;
use serde_json::json;

use crate::support::{
    CLIENT_SECRET, Env, FakeSecrets, KID_B, REFRESH_TOKEN, Reply, TestKey, base_config, code, key_a, key_b,
    nonce, verifier,
};

const MIN_REFETCH: Duration = Duration::from_secs(1);
const ESPERA: Duration = Duration::from_millis(1100);

fn con_kid(env: &Env, kid: &str) -> String {
    key_a().sign(&json!({"alg": "RS256", "typ": "JWT", "kid": kid}), &env.claims())
}

fn token_de(key: &TestKey, env: &Env) -> String {
    key.token(&env.claims())
}

/// Con un `kid` conocido y cache vigente no hay ninguna descarga adicional (solo la del
/// arranque): validar tokens legitimos no castiga a Cognito.
#[tokio::test]
async fn kid_conocido_no_descarga() {
    let env = Env::start_with(|c| c.jwks_min_refetch = MIN_REFETCH).await;
    assert_eq!(env.mock.jwks_hits(), 1, "warm_up");
    for _ in 0..5 {
        env.exchange(&token_de(key_a(), &env)).await.unwrap();
    }
    assert_eq!(env.mock.jwks_hits(), 1);
}

/// Un `kid` desconocido provoca exactamente una descarga (una vez pasado
/// `jwks_min_refetch`) y, si sigue sin aparecer, el token se rechaza.
#[tokio::test]
async fn kid_desconocido_provoca_una_descarga() {
    let env = Env::start_with(|c| c.jwks_min_refetch = MIN_REFETCH).await;
    tokio::time::sleep(ESPERA).await;
    env.assert_rejected(&con_kid(&env, "inventado")).await;
    assert_eq!(env.mock.jwks_hits(), 2);
}

/// Dentro de `jwks_min_refetch` desde la ultima descarga, un `kid` desconocido no vuelve
/// a descargar nada.
#[tokio::test]
async fn kid_desconocido_justo_tras_la_descarga_no_vuelve_a_descargar() {
    let env = Env::start_with(|c| c.jwks_min_refetch = Duration::from_secs(60)).await;
    env.assert_rejected(&con_kid(&env, "inventado")).await;
    assert_eq!(env.mock.jwks_hits(), 1);
}

/// DoS por `kid` inventados: un atacante manda muchos tokens con `kid` aleatorios
/// (secuenciales y concurrentes) para forzar descargas del JWKS. Como mucho una descarga
/// por ventana `jwks_min_refetch`; tokens legitimos siguen validando.
#[tokio::test]
async fn kids_inventados_no_provocan_mas_de_una_descarga_por_ventana() {
    let env = Arc::new(Env::start_with(|c| c.jwks_min_refetch = MIN_REFETCH).await);
    tokio::time::sleep(ESPERA).await;
    for i in 0..40 {
        env.assert_rejected(&con_kid(&env, &format!("kid-falso-{i}")))
            .await;
    }
    assert_eq!(env.mock.jwks_hits(), 2, "ventana 1: warm_up + una descarga");

    let mut tareas = Vec::new();
    for i in 0..30 {
        let env = env.clone();
        tareas.push(tokio::spawn(async move {
            env.assert_rejected(&con_kid(&env, &format!("concurrente-{i}")))
                .await;
        }));
    }
    for t in tareas {
        t.await.unwrap();
    }
    assert_eq!(env.mock.jwks_hits(), 2, "misma ventana: ninguna descarga mas");

    env.exchange(&token_de(key_a(), &env)).await.unwrap();
    assert_eq!(env.mock.jwks_hits(), 2);

    tokio::time::sleep(ESPERA).await;
    env.assert_rejected(&con_kid(&env, "otra-ventana")).await;
    assert_eq!(env.mock.jwks_hits(), 3, "ventana 2: una descarga");
}

/// Rotacion real de llaves: Cognito publica un `kid` nuevo; el primer token con ese
/// `kid` (pasado `jwks_min_refetch`) dispara el refetch y se acepta. El `kid` viejo deja
/// de validar si Cognito lo retira y el cache se renueva.
#[tokio::test]
async fn rotacion_de_llaves_se_acepta_tras_refetch() {
    let env = Env::start_with(|c| c.jwks_min_refetch = MIN_REFETCH).await;
    env.mock.publish_keys(vec![key_a().jwk(), key_b().jwk()]);
    tokio::time::sleep(ESPERA).await;
    assert!(env.exchange(&token_de(key_b(), &env)).await.is_ok());
    assert_eq!(env.mock.jwks_hits(), 2);
    assert!(env.exchange(&token_de(key_a(), &env)).await.is_ok());
    assert_eq!(env.mock.jwks_hits(), 2, "A sigue en cache");
    assert_eq!(key_b().kid, KID_B);
}

/// Una rotacion que ocurre antes de `jwks_min_refetch` no se acepta de inmediato
/// (proteccion contra descargas en bucle), pero si en cuanto pasa la ventana.
#[tokio::test]
async fn rotacion_dentro_de_la_ventana_espera_a_la_siguiente() {
    let env = Env::start_with(|c| c.jwks_min_refetch = MIN_REFETCH).await;
    env.mock.publish_keys(vec![key_a().jwk(), key_b().jwk()]);
    env.assert_rejected(&token_de(key_b(), &env)).await;
    assert_eq!(env.mock.jwks_hits(), 1);
    tokio::time::sleep(ESPERA).await;
    assert!(env.exchange(&token_de(key_b(), &env)).await.is_ok());
}

/// Al vencer `jwks_cache_ttl` se vuelve a descargar el JWKS, y una llave retirada deja de
/// validar (revocacion de una llave comprometida).
#[tokio::test]
async fn ttl_vencido_redescarga_y_la_llave_retirada_deja_de_valer() {
    let env = Env::start_with(|c| {
        c.jwks_cache_ttl = Duration::from_millis(800);
        c.jwks_min_refetch = Duration::from_millis(100);
    })
    .await;
    env.mock.publish_keys(vec![key_b().jwk()]);
    tokio::time::sleep(Duration::from_millis(900)).await;
    env.assert_rejected(&token_de(key_a(), &env)).await;
    assert_eq!(env.mock.jwks_hits(), 2);
    assert!(env.exchange(&token_de(key_b(), &env)).await.is_ok());
}

/// Si el JWKS vencio y Cognito falla, se sigue validando con el anterior (disponibilidad)
/// y el token firmado con la llave conocida se acepta.
#[tokio::test]
async fn jwks_vencido_con_cognito_caido_usa_el_cache_anterior() {
    let env = Env::start_with(|c| {
        c.jwks_cache_ttl = Duration::from_millis(300);
        c.jwks_min_refetch = Duration::from_millis(100);
    })
    .await;
    env.mock.set_jwks_status(503);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(env.exchange(&token_de(key_a(), &env)).await.is_ok());
    assert!(env.mock.jwks_hits() >= 2);
}

/// `CognitoIdp::new` falla rapido (transitorio) si el JWKS no se puede descargar.
#[tokio::test]
async fn arranque_con_jwks_caido_falla() {
    let env = Env::start().await;
    env.mock.set_jwks_status(503);
    let r = CognitoIdp::new(base_config(&env.mock), FakeSecrets::new(CLIENT_SECRET)).await;
    assert_eq!(r.err(), Some(AdapterError::Transient));
}

/// Un JWKS sin llaves RS256 utilizables (vacio) es un error permanente al arrancar.
#[tokio::test]
async fn arranque_con_jwks_sin_llaves_utilizables_falla() {
    let env = Env::start().await;
    env.mock.publish_keys(vec![]);
    let r = CognitoIdp::new(base_config(&env.mock), FakeSecrets::new(CLIENT_SECRET)).await;
    assert_eq!(r.err(), Some(AdapterError::Permanent));
}

/// Llaves del JWKS con `alg` o `use` que no sean RS256/sig (p. ej. una llave de cifrado)
/// no se usan para validar.
#[tokio::test]
async fn llaves_con_alg_o_use_incorrectos_se_descartan() {
    let env = Env::start().await;
    let mut enc = key_b().jwk();
    enc["use"] = json!("enc");
    let mut hs = key_b().jwk_as("hs");
    hs["alg"] = json!("HS256");
    env.mock.publish_keys(vec![key_a().jwk(), enc, hs]);
    let r = CognitoIdp::new(base_config(&env.mock), FakeSecrets::new(CLIENT_SECRET))
        .await
        .unwrap();
    env.mock
        .push_token(Reply::tokens(Some(&token_de(key_b(), &env)), Some(REFRESH_TOKEN)));
    let res = r.exchange_code(&code(), &verifier(), &nonce()).await;
    assert!(matches!(res, Err(IdpError::TokenRejected)), "{res:?}");
}

/// BUG (amplificacion de descargas): `JwksCache::key` solo actualiza `fetched_at` cuando
/// la descarga tiene exito. Con el JWKS de Cognito caido (5xx/timeout), cada token con
/// `kid` inventado repite la descarga (serializada tras el lock de escritura, hasta
/// `http_timeout` cada una), y `jwks_min_refetch` deja de proteger justo cuando mas hace
/// falta. Esperado: a lo sumo 1 intento por ventana.
#[tokio::test]
async fn kids_inventados_con_jwks_caido_no_deben_martillar_a_cognito() {
    let env = Env::start_with(|c| c.jwks_min_refetch = MIN_REFETCH).await;
    tokio::time::sleep(ESPERA).await;
    env.mock.set_jwks_status(503);
    for i in 0..20 {
        env.assert_rejected(&con_kid(&env, &format!("falso-{i}"))).await;
    }
    let intentos = env.mock.jwks_hits() - 1;
    assert!(
        intentos <= 1,
        "descargas durante la caida en una ventana: {intentos}"
    );
}
