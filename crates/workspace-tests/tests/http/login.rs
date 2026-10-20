//! `/auth/login` (§6.1): open redirect a traves de `returnTo` y usuario ya autenticado.

use axum::http::StatusCode;

use crate::support::{Env, PENDING_COOKIE, Req, enc, hash_of};

/// Open redirect: `returnTo` hostil nunca se respeta; tras un login completo el usuario
/// termina en `/`.
#[tokio::test(start_paused = true)]
async fn return_to_hostil_termina_en_la_raiz() {
    let env = Env::new();
    let hostiles = [
        "returnTo=https%3A%2F%2Fevil.com".to_owned(),
        "returnTo=%2F%2Fevil.com".to_owned(),
        format!("returnTo={}", enc("/\\evil.com")),
        format!("returnTo={}", enc("/%2F%2Fevil.com")),
        "returnTo=%2Fa&returnTo=%2Fb".to_owned(),
        "returnTo=%2Fa&returnTo=https%3A%2F%2Fevil.com".to_owned(),
        format!("returnTo={}", enc("javascript:alert(1)")),
        format!("returnTo={}", enc("/\r\nSet-Cookie: x=y")),
        format!("returnTo={}", enc("evil.com")),
        format!("returnTo={}", enc("/a\\..\\evil.com")),
        "returnTo=".to_owned(),
    ];
    for q in hostiles {
        let s = env.login(Some(&q)).await;
        assert_eq!(s.callback.status, StatusCode::SEE_OTHER, "{q}");
        assert_eq!(s.callback.location(), "/", "{q}");
    }
}

/// Un `returnTo` local valido, con query, se conserva exactamente.
#[tokio::test(start_paused = true)]
async fn return_to_local_valido_se_conserva() {
    let env = Env::new();
    let s = env.login(Some(&format!("returnTo={}", enc("/ruta?x=1")))).await;
    assert_eq!(s.callback.location(), "/ruta?x=1");
    let s = env.login(None).await;
    assert_eq!(s.callback.location(), "/");
}

/// El login manda al navegador a Cognito con `state`, `nonce` y PKCE, y guarda el login en
/// curso por hash (la cookie no es la clave del almacen).
#[tokio::test(start_paused = true)]
async fn login_redirige_al_idp_y_guarda_la_pending_por_hash() {
    let env = Env::new();
    let ini = env.iniciar(Some("returnTo=%2Fx")).await;
    assert!(
        ini.url.starts_with("https://idp.test/oauth2/authorize?"),
        "{}",
        ini.url
    );
    for p in ["state", "nonce", "code_challenge"] {
        assert!(!crate::support::query_param(&ini.url, p).is_empty());
    }
    assert!(ini.url.contains("code_challenge_method=S256"));
    assert!(!ini.url.contains("code_verifier"));
    assert_eq!(ini.pending.len(), 43);
    assert_eq!(env.ports.pending().len(), 1);
    assert!(!env.ports.pending().keys().contains(&ini.pending));
    assert_eq!(ini.resp.header("cache-control"), Some("no-store"));
}

/// Cada login en curso tiene state, nonce y cookie propios.
#[tokio::test(start_paused = true)]
async fn cada_login_tiene_state_nonce_y_pending_distintos() {
    let env = Env::new();
    let a = env.iniciar(None).await;
    let b = env.iniciar(None).await;
    assert_ne!(a.state, b.state);
    assert_ne!(a.pending, b.pending);
    assert_ne!(
        crate::support::query_param(&a.url, "nonce"),
        crate::support::query_param(&b.url, "nonce")
    );
}

/// Ya autenticado: `/auth/login` va directo a `returnTo`, sin pasar por Cognito y sin
/// cookie pending ni login en curso nuevo.
#[tokio::test(start_paused = true)]
async fn ya_autenticado_va_directo_a_return_to_sin_pending() {
    let env = Env::new();
    let id = env.sesion().await;
    let r = env
        .send(Req::get(&format!("/auth/login?returnTo={}", enc("/ruta?x=1"))).sesion(&id))
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/ruta?x=1");
    assert!(r.set_cookies().is_empty(), "{:?}", r.set_cookies());
    assert!(env.ports.pending().is_empty());
    assert_eq!(r.header("cache-control"), Some("no-store"));
}

/// Ya autenticado con `returnTo` hostil: tambien se va a `/`.
#[tokio::test(start_paused = true)]
async fn ya_autenticado_con_return_to_hostil_va_a_la_raiz() {
    let env = Env::new();
    let id = env.sesion().await;
    for q in [
        "returnTo=https%3A%2F%2Fevil.com",
        "returnTo=%2F%2Fevil.com",
        "returnTo=%2Fa&returnTo=%2Fb",
    ] {
        let r = env.send(Req::get(&format!("/auth/login?{q}")).sesion(&id)).await;
        assert_eq!(r.location(), "/", "{q}");
        assert!(r.set_cookies().is_empty());
    }
}

/// Con una cookie de sesion invalida el login sigue su curso normal (nueva pending) y el
/// usuario no queda "autenticado" por presentar basura.
#[tokio::test(start_paused = true)]
async fn con_sesion_invalida_el_login_sigue_a_cognito() {
    let env = Env::new();
    let r = env.send(Req::get("/auth/login").sesion(&"A".repeat(43))).await;
    assert!(r.location().starts_with("https://idp.test/"));
    assert!(r.cookie_fijada(PENDING_COOKIE).is_some());
    let borrada = hash_of(&"A".repeat(43));
    assert!(env.ports.sessions().snapshot(&borrada).is_none());
}

/// `returnTo` enorme (query de mas de 8 KiB) se ignora: login normal con destino `/`.
#[tokio::test(start_paused = true)]
async fn query_enorme_se_ignora() {
    let env = Env::new();
    let q = format!("returnTo=%2F{}", "a".repeat(9000));
    let s = env.login(Some(&q)).await;
    assert_eq!(s.callback.location(), "/");
}
