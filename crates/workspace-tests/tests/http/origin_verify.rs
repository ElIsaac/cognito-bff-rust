//! `X-Origin-Verify` (§7.3): solo el CloudFront propio puede hablar con el BFF.

use application::ports::AdapterError;
use axum::http::StatusCode;

use crate::support::{Env, Req, SECRETO_ACTUAL, SECRETO_PREVIO, assert_error};

const LOGIN: &str = "/auth/login";

fn con(valor: &str) -> Req {
    Req::get(LOGIN).sin_verify().header("x-origin-verify", valor)
}

fn assert_prohibido(r: &crate::support::Resp) {
    assert_error(r, StatusCode::FORBIDDEN, "forbidden");
    assert!(r.set_cookies().is_empty(), "{:?}", r.set_cookies());
}

/// Peticion directa al ALB sin la cabecera que pone CloudFront: 403, y no se ejecuta nada.
#[tokio::test(start_paused = true)]
async fn sin_cabecera_es_403() {
    let env = Env::con_origen();
    for ruta in [
        LOGIN,
        "/auth/me",
        "/auth/callback?error=x",
        "/api/orders",
        "/nada",
    ] {
        let r = env.send(Req::get(ruta).sin_verify()).await;
        assert_prohibido(&r);
    }
    assert!(env.ports.pending().is_empty(), "el login no debio ejecutarse");
    assert_eq!(
        env.secrets.lecturas(),
        0,
        "ni se consulta el secreto sin cabecera"
    );
}

/// Valor incorrecto, vacio, prefijo, extension o con otra capitalizacion: 403.
#[tokio::test(start_paused = true)]
async fn valor_incorrecto_es_403() {
    let env = Env::con_origen();
    let prefijo = &SECRETO_ACTUAL[..SECRETO_ACTUAL.len() - 1];
    let largo = format!("{SECRETO_ACTUAL}x");
    let mayusculas = SECRETO_ACTUAL.to_uppercase();
    for valor in [
        "incorrecto",
        "",
        prefijo,
        largo.as_str(),
        mayusculas.as_str(),
        SECRETO_PREVIO,
    ] {
        let r = env.send(con(valor)).await;
        assert_prohibido(&r);
    }
    assert!(env.ports.pending().is_empty());
}

/// Cabecera repetida: ambigua, 403 aunque una de las copias sea el valor correcto.
#[tokio::test(start_paused = true)]
async fn cabecera_duplicada_es_403() {
    let env = Env::con_origen();
    let casos = [
        (SECRETO_ACTUAL, SECRETO_ACTUAL),
        (SECRETO_ACTUAL, "otro"),
        ("otro", SECRETO_ACTUAL),
    ];
    for (a, b) in casos {
        let r = env.send(con(a).header("x-origin-verify", b)).await;
        assert_prohibido(&r);
    }
    assert!(env.ports.pending().is_empty());
}

/// Con el valor actual la peticion pasa.
#[tokio::test(start_paused = true)]
async fn valor_actual_pasa() {
    let env = Env::con_origen();
    let r = env.send(con(SECRETO_ACTUAL)).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(env.ports.pending().len(), 1);
}

/// Rotacion: durante la ventana pasan el valor actual y el anterior; al retirar el anterior,
/// el viejo deja de servir.
#[tokio::test(start_paused = true)]
async fn rotacion_acepta_el_valor_anterior() {
    let env = Env::con_origen();
    env.secrets.set_previous(Some(SECRETO_PREVIO));
    for valor in [SECRETO_ACTUAL, SECRETO_PREVIO] {
        let r = env.send(con(valor)).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{valor}");
    }
    let r = env.send(con("tercero")).await;
    assert_prohibido(&r);

    env.secrets.set_previous(None);
    let r = env.send(con(SECRETO_PREVIO)).await;
    assert_prohibido(&r);
    let r = env.send(con(SECRETO_ACTUAL)).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

/// Secrets Manager caido: falla cerrado con 500 (nunca deja pasar), sin detalles, tambien con
/// el valor correcto; al recuperarse vuelve a servir.
#[tokio::test(start_paused = true)]
async fn error_del_proveedor_de_secretos_falla_cerrado() {
    let env = Env::con_origen();
    for e in [AdapterError::Transient, AdapterError::Permanent] {
        env.secrets.fail_with(Some(e));
        let r = env.send(con(SECRETO_ACTUAL)).await;
        assert_error(&r, StatusCode::INTERNAL_SERVER_ERROR, "internal");
        let r = env
            .send(
                Req::get("/api/orders")
                    .sin_verify()
                    .header("x-origin-verify", "incorrecto"),
            )
            .await;
        assert_error(&r, StatusCode::INTERNAL_SERVER_ERROR, "internal");
        assert!(!r.text().contains("transitorio") && !r.text().contains("permanente"));
    }
    assert!(env.ports.pending().is_empty());
    env.secrets.fail_with(None);
    let r = env.send(con(SECRETO_ACTUAL)).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

/// El secreto de origen no llega al upstream ni se devuelve al cliente.
#[tokio::test(start_paused = true)]
async fn la_cabecera_no_se_reenvia_al_upstream() {
    let env = Env::con_origen();
    let id = env.sesion().await;
    let r = env.send(Req::get("/api/orders").sesion(&id)).await;
    assert_eq!(r.status, StatusCode::OK);
    let reqs = env.ports.upstream().requests();
    assert_eq!(reqs.len(), 1);
    assert!(
        reqs[0]
            .headers
            .iter()
            .all(|(k, v)| k != "x-origin-verify" && !v.contains(SECRETO_ACTUAL))
    );
    assert!(!format!("{:?}", r.headers).contains(SECRETO_ACTUAL));
}

/// Cada peticion con exactamente una cabecera consulta el proveedor (cacheado por el
/// adaptador real); las rechazadas por forma no lo consultan.
#[tokio::test(start_paused = true)]
async fn el_proveedor_se_consulta_una_vez_por_peticion_valida_en_forma() {
    let env = Env::con_origen();
    env.send(con(SECRETO_ACTUAL)).await;
    env.send(con("incorrecto")).await;
    assert_eq!(env.secrets.lecturas(), 2);
    env.send(Req::get(LOGIN).sin_verify()).await;
    env.send(con("a").header("x-origin-verify", "b")).await;
    assert_eq!(env.secrets.lecturas(), 2);
}

/// Sin secreto configurado la cabecera se ignora: falte, sobre o se repita; no se consulta
/// el proveedor y tampoco llega al upstream.
#[tokio::test(start_paused = true)]
async fn sin_configurar_la_cabecera_se_ignora() {
    let env = Env::new();
    let r = env.send(Req::get(LOGIN).sin_verify()).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let r = env.send(con("cualquiera")).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let r = env.send(con("a").header("x-origin-verify", "b")).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(env.secrets.lecturas(), 0);

    env.secrets.fail_with(Some(AdapterError::Permanent));
    let id = env.sesion().await;
    let r = env
        .send(
            Req::get("/api/orders")
                .sesion(&id)
                .header("x-origin-verify", "cualquiera"),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let up = env.ports.upstream().requests();
    assert!(up[0].headers.iter().all(|(k, _)| k != "x-origin-verify"));
}
