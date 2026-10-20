//! `/auth/me` (§6.3): forma de la respuesta y ausencia de tokens.

use axum::http::StatusCode;

use crate::support::{Env, Req, SESSION_COOKIE, TENANT, assert_error};

/// Forma exacta `{sub,email,name,groups,attributes}`: ningun token ni id de sesion sale al
/// navegador.
#[tokio::test(start_paused = true)]
async fn me_devuelve_solo_el_perfil_sin_tokens() {
    let env = Env::new();
    let id = env.sesion().await;
    let access = env.access_de(&id);
    let refresh = env
        .ports
        .sessions()
        .snapshot(&crate::support::hash_of(&id))
        .unwrap()
        .tokens
        .refresh
        .expose_secret()
        .to_owned();

    let r = env.send(Req::get("/auth/me").sesion(&id)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert!(r.set_cookies().is_empty());

    let body = r.json();
    let obj = body.as_object().unwrap();
    let mut claves: Vec<&str> = obj.keys().map(String::as_str).collect();
    claves.sort_unstable();
    assert_eq!(claves, ["attributes", "email", "groups", "name", "sub"]);
    assert_eq!(body["sub"], "user-1");
    assert_eq!(body["email"], "ana@example.com");
    assert_eq!(body["name"], "Ana");
    assert_eq!(body["groups"], serde_json::json!(["admins", "ventas"]));
    assert_eq!(
        body["attributes"],
        serde_json::json!({ "custom:tenant_id": TENANT })
    );

    let crudo = format!("{:?} {}", r.headers, r.text());
    for secreto in [&access, &refresh, &id] {
        assert!(!crudo.contains(secreto.as_str()), "fuga: {secreto}");
    }
    assert!(!crudo.to_lowercase().contains("token"));
}

/// Sin sesion: 401 con el cuerpo estandar y la cookie borrada.
#[tokio::test(start_paused = true)]
async fn me_sin_sesion_es_401() {
    let env = Env::new();
    let r = env.send(Req::get("/auth/me")).await;
    assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    assert!(r.borra_cookie(SESSION_COOKIE));
}

/// Sesion vencida (expiracion absoluta o inactividad): 401 igual que sin sesion.
#[tokio::test(start_paused = true)]
async fn me_con_sesion_vencida_es_401() {
    let env = Env::new();
    let id = env.sesion().await;
    env.advance_secs(13 * 3600).await;
    let r = env.send(Req::get("/auth/me").sesion(&id)).await;
    assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    assert!(r.borra_cookie(SESSION_COOKIE));
}
