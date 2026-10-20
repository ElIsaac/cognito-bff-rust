//! `/auth/callback` (§6.2): siempre termina en 303, nunca refleja datos del atacante y no
//! crea sesion si falla.

use axum::http::StatusCode;

use crate::support::{Env, PENDING_COOKIE, Req, Resp, SESSION_COOKIE, enc};

fn assert_fallo(resp: &Resp, code: &str) {
    assert_eq!(resp.status, StatusCode::SEE_OTHER);
    assert_eq!(resp.location(), format!("/?code={code}"));
    assert!(resp.body.is_empty(), "el redirect no lleva cuerpo");
    assert!(
        resp.cookie_fijada(SESSION_COOKIE).is_none(),
        "fijo sesion en un fallo"
    );
    assert!(resp.borra_cookie(PENDING_COOKIE));
    assert_eq!(resp.header("cache-control"), Some("no-store"));
}

/// Callback sin la cookie de login en curso (CSRF de login o cookie perdida): `missing_pending`.
#[tokio::test(start_paused = true)]
async fn sin_cookie_pending_es_missing_pending() {
    let env = Env::new();
    let ini = env.iniciar(None).await;
    let code = env.emitir_code(&ini);
    let r = env
        .send(Req::get(&format!(
            "/auth/callback?code={code}&state={}",
            ini.state
        )))
        .await;
    assert_fallo(&r, "missing_pending");
    assert!(env.ports.sessions().is_empty());
    assert_eq!(
        env.ports.idp().exchange_calls(),
        0,
        "no se canjea nada sin pending"
    );
}

/// Cookie pending malformada o repetida equivale a no tenerla.
#[tokio::test(start_paused = true)]
async fn pending_malformada_o_repetida_es_missing_pending() {
    let env = Env::new();
    let ini = env.iniciar(None).await;
    let code = env.emitir_code(&ini);
    let uri = format!("/auth/callback?code={code}&state={}", ini.state);
    let p = &ini.pending;
    for cookie in [
        format!("{PENDING_COOKIE}={p}x!"),
        format!("{PENDING_COOKIE}={p}; {PENDING_COOKIE}={p}"),
        format!("{PENDING_COOKIE}="),
    ] {
        let r = env.send(Req::get(&uri).header("cookie", &cookie)).await;
        assert_fallo(&r, "missing_pending");
    }
    assert_eq!(env.ports.idp().exchange_calls(), 0);
}

/// Login fijado por un atacante: el `state` no es el de este navegador.
#[tokio::test(start_paused = true)]
async fn state_incorrecto_es_invalid_state() {
    let env = Env::new();
    let ini = env.iniciar(None).await;
    let ajeno = env.iniciar(None).await;
    let code = env.emitir_code(&ini);
    for state in [
        ajeno.state.clone(),
        "x".repeat(43),
        "corto".to_owned(),
        String::new(),
    ] {
        let ini2 = env.iniciar(None).await;
        let r = env
            .send(
                Req::get(&format!("/auth/callback?code={code}&state={state}"))
                    .cookie(PENDING_COOKIE, &ini2.pending),
            )
            .await;
        assert_fallo(&r, "invalid_state");
    }
    assert_eq!(env.ports.idp().exchange_calls(), 0);
    assert!(env.ports.sessions().is_empty());
}

/// State faltante tambien es `invalid_state`.
#[tokio::test(start_paused = true)]
async fn state_ausente_es_invalid_state() {
    let env = Env::new();
    let ini = env.iniciar(None).await;
    let code = env.emitir_code(&ini);
    let r = env
        .send(Req::get(&format!("/auth/callback?code={code}")).cookie(PENDING_COOKIE, &ini.pending))
        .await;
    assert_fallo(&r, "invalid_state");
}

/// Replay del callback: el segundo intento con la misma cookie y la misma URL falla porque
/// el login en curso se consume; solo queda la sesion del primero.
#[tokio::test(start_paused = true)]
async fn replay_del_callback_es_invalid_state() {
    let env = Env::new();
    let ini = env.iniciar(Some("returnTo=%2Fruta")).await;
    let code = env.emitir_code(&ini);
    let primero = env.callback(&ini, &code).await;
    assert_eq!(primero.status, StatusCode::SEE_OTHER);
    assert_eq!(primero.location(), "/ruta");
    assert!(primero.cookie_fijada(SESSION_COOKIE).is_some());

    let segundo = env.callback(&ini, &code).await;
    assert_fallo(&segundo, "invalid_state");
    assert_eq!(env.ports.sessions().len(), 1);
    assert_eq!(env.ports.idp().exchange_calls(), 1);
}

/// El usuario cancela en el Hosted UI: `access_denied`.
#[tokio::test(start_paused = true)]
async fn error_access_denied_del_proveedor() {
    let env = Env::new();
    let ini = env.iniciar(None).await;
    let r = env
        .send(
            Req::get(&format!("/auth/callback?error=access_denied&state={}", ini.state))
                .cookie(PENDING_COOKIE, &ini.pending),
        )
        .await;
    assert_fallo(&r, "access_denied");
}

/// Un valor de `error` desconocido (o hostil) se reduce a `provider_error`; el valor nunca
/// se refleja.
#[tokio::test(start_paused = true)]
async fn error_desconocido_es_provider_error() {
    let env = Env::new();
    for error in [
        "server_error",
        "temporarily_unavailable",
        "<script>alert(1)</script>",
        "",
        "ACCESS_DENIED",
    ] {
        let ini = env.iniciar(None).await;
        let r = env
            .send(
                Req::get(&format!(
                    "/auth/callback?error={}&state={}",
                    enc(error),
                    ini.state
                ))
                .cookie(PENDING_COOKIE, &ini.pending),
            )
            .await;
        assert_fallo(&r, "provider_error");
    }
}

/// `state` repetido es ambiguo (HPP): se rechaza aunque uno de los valores sea correcto.
#[tokio::test(start_paused = true)]
async fn state_duplicado_se_rechaza() {
    let env = Env::new();
    for orden in 0..2 {
        let ini = env.iniciar(None).await;
        let code = env.emitir_code(&ini);
        let (a, b) = if orden == 0 {
            (ini.state.as_str(), "otro")
        } else {
            ("otro", ini.state.as_str())
        };
        let r = env
            .send(
                Req::get(&format!("/auth/callback?code={code}&state={a}&state={b}"))
                    .cookie(PENDING_COOKIE, &ini.pending),
            )
            .await;
        assert_fallo(&r, "invalid_state");
    }
    assert_eq!(env.ports.idp().exchange_calls(), 0);
}

/// `code` ausente, vacio o repetido es `invalid_request` y no se llama al IdP.
#[tokio::test(start_paused = true)]
async fn code_ausente_o_repetido_es_invalid_request() {
    let env = Env::new();
    for extra in ["", "&code=", "&code=a&code=b"] {
        let ini = env.iniciar(None).await;
        let r = env
            .send(
                Req::get(&format!("/auth/callback?state={}{extra}", ini.state))
                    .cookie(PENDING_COOKIE, &ini.pending),
            )
            .await;
        assert_fallo(&r, "invalid_request");
    }
    assert_eq!(env.ports.idp().exchange_calls(), 0);
}

/// Un code que el IdP rechaza (ya usado o inventado) es `exchange_failed`.
#[tokio::test(start_paused = true)]
async fn code_invalido_es_exchange_failed() {
    let env = Env::new();
    let ini = env.iniciar(None).await;
    let r = env.callback(&ini, "code-inventado-por-el-atacante").await;
    assert_fallo(&r, "exchange_failed");
    assert!(env.ports.sessions().is_empty());
}

/// `error_description` (texto libre y controlable por un atacante) no se refleja en el
/// redirect, ni en el cuerpo ni en ninguna cabecera.
#[tokio::test(start_paused = true)]
async fn el_redirect_de_error_no_refleja_error_description() {
    let env = Env::new();
    let veneno = "<script>alert('xss')</script>\r\nSet-Cookie: a=b";
    for error in ["access_denied", "server_error"] {
        let ini = env.iniciar(None).await;
        let uri = format!(
            "/auth/callback?error={error}&error_description={}&state={}",
            enc(veneno),
            ini.state
        );
        let r = env
            .send(Req::get(&uri).cookie(PENDING_COOKIE, &ini.pending))
            .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER);
        let esperado = if error == "access_denied" {
            "access_denied"
        } else {
            "provider_error"
        };
        assert_eq!(r.location(), format!("/?code={esperado}"));
        let todo = format!("{:?} {}", r.headers, r.text());
        for traza in ["script", "xss", "alert", "a=b"] {
            assert!(!todo.contains(traza), "refleja {traza}: {todo}");
        }
    }
}

/// Ningun fallo del callback deja una cookie de sesion ni una sesion en el almacen.
#[tokio::test(start_paused = true)]
async fn ningun_fallo_fija_sesion() {
    let env = Env::new();
    let consultas = [
        String::new(),
        "error=access_denied".to_owned(),
        "code=a&state=b".to_owned(),
        "state=solo".to_owned(),
        "code=a&code=b&state=c".to_owned(),
    ];
    for q in consultas {
        let ini = env.iniciar(None).await;
        for con_pending in [true, false] {
            let mut req = Req::get(&format!("/auth/callback?{q}"));
            if con_pending {
                req = req.cookie(PENDING_COOKIE, &ini.pending);
            }
            let r = env.send(req).await;
            assert_eq!(r.status, StatusCode::SEE_OTHER, "{q}");
            assert!(r.cookie_fijada(SESSION_COOKIE).is_none(), "{q}");
            assert!(r.location().starts_with("/?code="), "{q}");
        }
    }
    assert!(env.ports.sessions().is_empty());
}

/// El destino del error viene de la configuracion, no de la peticion: `returnTo` o un
/// `Referer` en el callback no cambian a donde va el error.
#[tokio::test(start_paused = true)]
async fn el_destino_del_error_es_fijo() {
    let env = Env::new();
    let r = env
        .send(
            Req::get("/auth/callback?returnTo=https%3A%2F%2Fevil.com&error=access_denied")
                .header("referer", "https://evil.com/"),
        )
        .await;
    assert_fallo(&r, "missing_pending");
}
