//! CSRF (§7.2) sobre HTTP: toda ruta que cambia estado exige `X-Requested-With` y no acepta
//! `Origin` ni `Sec-Fetch-Site` ajenos.

use axum::http::{Method, StatusCode};

use crate::support::{Env, Req, assert_error};

const ORIGEN_AJENO: &str = "https://evil.com";

/// `(metodo, ruta, cuerpo JSON)` de cada ruta protegida.
fn protegidas() -> Vec<(Method, &'static str, &'static str)> {
    let mut v = vec![
        (Method::POST, "/auth/logout", ""),
        (Method::POST, "/auth/ws-ticket", ""),
        (Method::POST, "/auth/account/mfa/totp/associate", ""),
        (
            Method::POST,
            "/auth/account/mfa/totp/verify",
            r#"{"code":"123456"}"#,
        ),
        (Method::POST, "/auth/account/mfa/preference", r#"{"totp":false}"#),
        (
            Method::POST,
            "/auth/account/change-password",
            r#"{"previousPassword":"Inicial-123","proposedPassword":"Nueva-clave-456"}"#,
        ),
    ];
    for m in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
        v.push((m, "/api/orders", r#"{"a":1}"#));
    }
    v
}

fn peticion(m: &Method, ruta: &str, cuerpo: &str, id: &str) -> Req {
    let r = Req::new(m.clone(), ruta).sesion(id);
    if cuerpo.is_empty() { r } else { r.json(cuerpo) }
}

/// Nada de esto debe haber ocurrido si el CSRF rechazo la peticion.
fn assert_sin_efectos(env: &Env, id: &str) {
    assert_eq!(env.ports.upstream().request_count(), 0, "llego al upstream");
    assert!(env.ports.tickets().is_empty(), "emitio boleto");
    assert!(env.ports.account().calls().is_empty(), "llamo a Cognito");
    assert_eq!(env.ports.idp().revoke_calls(), 0, "revoco el refresh");
    assert!(
        env.ports
            .sessions()
            .snapshot(&crate::support::hash_of(id))
            .is_some(),
        "borro la sesion"
    );
}

async fn assert_todas_403(extra: impl Fn(Req) -> Req) {
    let env = Env::new();
    let id = env.sesion().await;
    for (m, ruta, cuerpo) in protegidas() {
        let r = env.send(extra(peticion(&m, ruta, cuerpo, &id))).await;
        assert_error(&r, StatusCode::FORBIDDEN, "csrf");
        assert_eq!(r.json()["error"], "csrf", "{m} {ruta}");
        assert!(r.cookie_fijada(crate::support::SESSION_COOKIE).is_none());
    }
    assert_sin_efectos(&env, &id);
}

/// CSRF clasico: un formulario de otro sitio no puede poner la cabecera personalizada.
#[tokio::test(start_paused = true)]
async fn sin_cabecera_x_requested_with_es_403() {
    assert_todas_403(|r| r).await;
}

/// Aun sin la cabecera y con `Origin` propio (que un navegador pone solo): no basta.
#[tokio::test(start_paused = true)]
async fn origin_propio_sin_cabecera_tampoco_basta() {
    assert_todas_403(|r| r.header("origin", crate::support::ORIGIN)).await;
}

/// Peticion cross-site con la cabecera presente (CORS mal configurado en otro sitio).
#[tokio::test(start_paused = true)]
async fn sec_fetch_site_cross_site_es_403() {
    for valor in ["cross-site", "same-site", ""] {
        assert_todas_403(|r| r.csrf().header("sec-fetch-site", valor)).await;
    }
}

/// `Origin` ajeno con la cabecera presente.
#[tokio::test(start_paused = true)]
async fn origin_ajeno_es_403() {
    for origen in [
        ORIGEN_AJENO,
        "null",
        "https://app.example.com.evil.com",
        "http://app.example.com",
    ] {
        assert_todas_403(|r| r.csrf().header("origin", origen)).await;
    }
}

/// Dos `Origin` (uno propio y uno ajeno): ambiguo, se rechaza.
#[tokio::test(start_paused = true)]
async fn origin_duplicado_es_403() {
    assert_todas_403(|r| {
        r.csrf()
            .header("origin", crate::support::ORIGIN)
            .header("origin", ORIGEN_AJENO)
    })
    .await;
    assert_todas_403(|r| {
        r.csrf()
            .header("origin", crate::support::ORIGIN)
            .header("origin", crate::support::ORIGIN)
    })
    .await;
}

/// La cabecera anti-CSRF repetida tambien es ambigua.
#[tokio::test(start_paused = true)]
async fn cabecera_csrf_duplicada_es_403() {
    assert_todas_403(|r| r.csrf().csrf()).await;
}

/// El CSRF se evalua antes que la sesion: sin cookie y sin cabecera es 403 (no 401), asi el
/// atacante no usa el codigo para sondear si hay sesion.
#[tokio::test(start_paused = true)]
async fn csrf_se_evalua_antes_que_la_sesion() {
    let env = Env::new();
    for (m, ruta, cuerpo) in protegidas() {
        let r = env.send(Req::new(m.clone(), ruta).json(cuerpo)).await;
        assert_error(&r, StatusCode::FORBIDDEN, "csrf");
        assert!(r.set_cookies().is_empty(), "{m} {ruta}: el 403 no borra cookies");
    }
}

/// Control positivo: con la cabecera y el `Origin`/`Sec-Fetch-Site` propios, ninguna ruta
/// protegida responde 403.
#[tokio::test(start_paused = true)]
async fn con_cabecera_y_origin_propios_pasa() {
    for (m, ruta, cuerpo) in protegidas() {
        let env = Env::new();
        let id = env.sesion().await;
        let r = env
            .send(
                peticion(&m, ruta, cuerpo, &id)
                    .csrf()
                    .header("origin", crate::support::ORIGIN)
                    .header("sec-fetch-site", "same-origin"),
            )
            .await;
        // El verify sin associate previo es 400 de dominio; lo que importa es que no sea CSRF.
        assert!(
            r.status.is_success() || r.json()["error"] == "mfa_setup_invalid",
            "{m} {ruta}: {} {}",
            r.status,
            r.text()
        );
    }
}

/// Los metodos seguros no exigen la cabecera.
#[tokio::test(start_paused = true)]
async fn get_pasa_sin_cabecera() {
    let env = Env::new();
    let id = env.sesion().await;
    for ruta in ["/auth/me", "/auth/account/mfa", "/api/orders"] {
        let r = env.send(Req::get(ruta).sesion(&id)).await;
        assert_eq!(r.status, StatusCode::OK, "{ruta}");
    }
    let r = env.send(Req::get("/auth/login")).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

/// Metodos desconocidos (`TRACE`, `CONNECT`, extension) dan 405 antes de cualquier otra cosa,
/// tambien con la cabecera CSRF y sobre rutas que no existen.
#[tokio::test(start_paused = true)]
async fn metodos_desconocidos_dan_405() {
    let env = Env::new();
    let id = env.sesion().await;
    for nombre in ["TRACE", "CONNECT", "PROPFIND", "BREW"] {
        let m = Method::from_bytes(nombre.as_bytes()).unwrap();
        for ruta in ["/auth/me", "/api/orders", "/auth/logout", "/nada"] {
            for con_csrf in [false, true] {
                let mut req = Req::new(m.clone(), ruta).sesion(&id);
                if con_csrf {
                    req = req.csrf();
                }
                let r = env.send(req).await;
                assert_error(&r, StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
            }
        }
    }
    assert_eq!(env.ports.upstream().request_count(), 0);
}

/// Un metodo permitido por el proxy pero no por la ruta (`POST /auth/me`) con la cabecera
/// correcta es 405, no 200.
#[tokio::test(start_paused = true)]
async fn metodo_no_soportado_por_la_ruta_es_405() {
    let env = Env::new();
    let id = env.sesion().await;
    for (m, ruta) in [
        (Method::POST, "/auth/me"),
        (Method::DELETE, "/auth/me"),
        (Method::GET, "/auth/logout"),
        (Method::PUT, "/auth/ws-ticket"),
        (Method::POST, "/auth/login"),
        (Method::POST, "/auth/callback"),
    ] {
        let r = env.send(Req::new(m.clone(), ruta).sesion(&id).csrf()).await;
        assert_error(&r, StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
    }
}

/// `Origin`, `Sec-Fetch-Site` o la cabecera CSRF con bytes no ASCII (ilegibles como texto)
/// deben tratarse como presentes y rechazarse, no como ausentes ni como una sola copia.
#[tokio::test(start_paused = true)]
async fn cabeceras_ilegibles_se_rechazan() {
    let env = Env::new();
    let id = env.sesion().await;
    let ilegible: &[u8] = b"https://app.example.com\xff";
    let casos = [
        Req::post("/auth/logout")
            .sesion(&id)
            .csrf()
            .header_bytes("origin", ilegible),
        Req::post("/auth/logout")
            .sesion(&id)
            .csrf()
            .header("origin", crate::support::ORIGIN)
            .header_bytes("origin", ilegible),
        Req::post("/auth/logout")
            .sesion(&id)
            .csrf()
            .header_bytes("sec-fetch-site", b"same-origin\xff"),
        Req::post("/auth/logout")
            .sesion(&id)
            .csrf()
            .header_bytes(crate::support::CSRF_HEADER, b"\xff"),
    ];
    for req in casos {
        let r = env.send(req).await;
        assert_error(&r, StatusCode::FORBIDDEN, "csrf");
    }
    assert!(
        env.ports
            .sessions()
            .snapshot(&crate::support::hash_of(&id))
            .is_some()
    );
}
