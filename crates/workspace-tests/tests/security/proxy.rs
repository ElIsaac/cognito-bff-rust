//! Proxy `/api/*`: validacion de ruta y body, listas blancas de cabeceras y errores.

use application::ports::{Header, Method, UpstreamError, UpstreamResponse};
use application::{AppError, ProxyCall};

use crate::common::{Env, MAX_BODY, login, stored};

fn h(k: &str, v: &str) -> Header {
    (k.to_owned(), v.to_owned())
}

fn get<'a>(cookie: &'a str, path: &'a str, headers: &'a [Header]) -> ProxyCall<'a> {
    ProxyCall {
        session_cookie: Some(cookie),
        method: Method::Get,
        path,
        query: None,
        headers,
        body: Vec::new(),
    }
}

/// Path traversal y cambio de host: ninguna de estas rutas llega al upstream ni provoca
/// llamadas al IdP; la respuesta es `BadRequest`.
#[tokio::test(start_paused = true)]
async fn rutas_invalidas_son_bad_request_sin_llamar_a_nadie() {
    let env = Env::new();
    let cookie = login(&env).await;
    let canjes = env.ports.idp().exchange_calls();
    let rutas = [
        "../auth/me",
        "%2e%2e/",
        "%2E%2E/auth/me",
        "..%2f",
        "..%2Fauth",
        "x/../../",
        "x/./y",
        "x/%2e%2e/y",
        "https://evil",
        "//evil.com/x",
        "/abs",
        "a%5cb",
        "a%2fb",
        "a%00b",
        "a%252e",
        "a\\b",
        "a b",
        "a\r\nHost: evil",
        "a?x=1",
        "a#f",
        "%zz",
        &"a".repeat(5000),
    ];
    for ruta in rutas {
        let r = env.app.proxy(get(&cookie, ruta, &[])).await;
        assert_eq!(r.unwrap_err(), AppError::BadRequest, "ruta {ruta:?}");
    }
    assert_eq!(env.ports.upstream().request_count(), 0);
    assert_eq!(env.ports.idp().refresh_calls(), 0);
    assert_eq!(env.ports.idp().exchange_calls(), canjes);
}

/// Rutas legitimas con apariencia sospechosa siguen funcionando y se reenvian tal cual.
#[tokio::test(start_paused = true)]
async fn rutas_normales_se_reenvian() {
    let env = Env::new();
    let cookie = login(&env).await;
    for ruta in [
        "orders",
        "orders/42",
        "a-b_c.d/e~f",
        "orders/",
        "file.v1.json",
        "%7Euser",
    ] {
        env.app
            .proxy(get(&cookie, ruta, &[]))
            .await
            .unwrap_or_else(|e| panic!("{ruta}: {e:?}"));
    }
    let reqs = env.ports.upstream().requests();
    assert_eq!(reqs.len(), 6);
    assert_eq!(reqs[1].path.as_str(), "orders/42");
}

/// DoS por body enorme: mas de `proxy_max_body` es `PayloadTooLarge` y no se reenvia; justo
/// en el limite pasa.
#[tokio::test(start_paused = true)]
async fn body_mayor_al_limite_es_payload_too_large() {
    let env = Env::new();
    let cookie = login(&env).await;
    let call = |body: Vec<u8>| ProxyCall {
        session_cookie: Some(&cookie),
        method: Method::Post,
        path: "upload",
        query: None,
        headers: &[],
        body,
    };
    let r = env.app.proxy(call(vec![0; MAX_BODY + 1])).await;
    assert_eq!(r.unwrap_err(), AppError::PayloadTooLarge);
    assert_eq!(env.ports.upstream().request_count(), 0);

    env.app.proxy(call(vec![0; MAX_BODY])).await.unwrap();
    assert_eq!(env.ports.upstream().request_count(), 1);
}

/// El limite configurado no puede superar el tope duro (5 MiB) aunque se pida mas.
#[tokio::test(start_paused = true)]
async fn el_limite_de_body_tiene_tope_duro() {
    let cfg = crate::common::config().with_proxy_max_body(usize::MAX);
    assert_eq!(cfg.proxy_max_body, application::PROXY_MAX_BODY_HARD_CAP);
}

/// Suplantacion de identidad hacia el upstream y smuggling: ninguna de las cabeceras
/// prohibidas llega al upstream; el `Authorization` lo pone el BFF con el access token de la
/// sesion (el del cliente se ignora).
#[tokio::test(start_paused = true)]
async fn cabeceras_prohibidas_no_llegan_al_upstream() {
    let env = Env::new();
    let cookie = login(&env).await;
    let access = stored(&env, &cookie).tokens.access.expose_secret().to_owned();
    let prohibidas = [
        "cookie",
        "host",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "forwarded",
        "x-real-ip",
        "authorization",
        "x-origin-verify",
        "origin",
        "referer",
        "x-requested-with",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-connection",
        "content-length",
        "x-amzn-trace-id",
    ];
    let mut headers: Vec<Header> = prohibidas.iter().map(|n| h(n, "valor-del-atacante")).collect();
    headers.push(h("authorization", "Bearer token-del-atacante"));
    headers.extend([
        h("accept", "application/json"),
        h("content-type", "application/json"),
        h("x-request-id", "req-1"),
        h("traceparent", "00-aaaa-bbbb-01"),
        h("x-request-id", "malo\r\nX-Evil: 1"),
    ]);
    let call = ProxyCall {
        session_cookie: Some(&cookie),
        method: Method::Post,
        path: "orders",
        query: Some("a=1&b=2"),
        headers: &headers,
        body: b"{}".to_vec(),
    };
    env.app.proxy(call).await.unwrap();

    let reqs = env.ports.upstream().requests();
    assert_eq!(reqs.len(), 1);
    let req = &reqs[0];
    let nombres: Vec<&str> = req.headers.iter().map(|(k, _)| k.as_str()).collect();
    for n in prohibidas {
        assert!(!nombres.contains(&n), "{n} llego al upstream");
    }
    assert_eq!(nombres, ["accept", "content-type", "x-request-id", "traceparent"]);
    assert!(
        req.headers
            .iter()
            .all(|(_, v)| v != "valor-del-atacante" && !v.contains("atacante"))
    );
    assert_eq!(req.bearer.expose_secret(), access);
    assert_eq!(req.method, Method::Post);
    assert_eq!(req.path.as_str(), "orders");
    assert_eq!(req.query.as_deref(), Some("a=1&b=2"));
    assert_eq!(req.body, b"{}");
}

/// El bearer del upstream es siempre el access token de la sesion, tambien el recien
/// refrescado (nunca uno viejo ni uno enviado por el cliente).
#[tokio::test(start_paused = true)]
async fn el_bearer_es_el_access_token_refrescado() {
    let env = Env::new();
    let cookie = login(&env).await;
    let viejo = stored(&env, &cookie).tokens.access.expose_secret().to_owned();
    env.advance_secs(3600 - 30).await;

    env.app
        .proxy(get(&cookie, "x", &[h("authorization", "Bearer otro")]))
        .await
        .unwrap();
    let nuevo = stored(&env, &cookie).tokens.access.expose_secret().to_owned();
    assert_ne!(nuevo, viejo);
    let reqs = env.ports.upstream().requests();
    assert_eq!(reqs[0].bearer.expose_secret(), nuevo);
}

/// Sin sesion no se reenvia nada: `Unauthorized`.
#[tokio::test(start_paused = true)]
async fn sin_sesion_el_proxy_responde_unauthorized() {
    let env = Env::new();
    let mut call = get("basura", "orders", &[]);
    assert_eq!(env.app.proxy(call).await.unwrap_err(), AppError::Unauthorized);
    call = get("x", "orders", &[]);
    call.session_cookie = None;
    assert_eq!(env.app.proxy(call).await.unwrap_err(), AppError::Unauthorized);
    assert_eq!(env.ports.upstream().request_count(), 0);
}

/// Un upstream comprometido o mal configurado no puede plantar cookies en el navegador ni
/// inyectar cabeceras de CORS/HSTS/hop-by-hop: se filtran. El status y el body pasan tal cual.
#[tokio::test(start_paused = true)]
async fn set_cookie_y_cabeceras_peligrosas_del_upstream_no_vuelven() {
    let env = Env::new();
    let cookie = login(&env).await;
    env.ports.upstream().respond_with(UpstreamResponse {
        status: 201,
        headers: vec![
            h("set-cookie", "__Host-bff_session=fijada; Path=/"),
            h("set-cookie2", "x=y"),
            h("connection", "close"),
            h("keep-alive", "timeout=5"),
            h("transfer-encoding", "chunked"),
            h("content-length", "3"),
            h("upgrade", "websocket"),
            h("proxy-authenticate", "Basic"),
            h("strict-transport-security", "max-age=0"),
            h("access-control-allow-origin", "https://evil.com"),
            h("access-control-allow-credentials", "true"),
            h("content-type", "application/json"),
            h("etag", "\"abc\""),
            h("x-custom", "malo\r\nSet-Cookie: a=b"),
        ],
        body: b"hola".to_vec(),
    });
    let resp = env.app.proxy(get(&cookie, "orders", &[])).await.unwrap();
    assert_eq!(resp.status, 201);
    assert_eq!(resp.body, b"hola");
    let nombres: Vec<&str> = resp.headers.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(nombres, ["content-type", "etag"]);
}

/// Endurecimiento pendiente: el filtro de respuesta compara nombres exactos en minuscula;
/// si un adaptador devolviera `Set-Cookie` con mayusculas el filtro no lo veria. El contrato
/// del puerto exige minusculas, pero conviene que `application` no dependa de ello.
#[tokio::test(start_paused = true)]
async fn set_cookie_con_mayusculas_tambien_se_filtra() {
    let env = Env::new();
    let cookie = login(&env).await;
    env.ports.upstream().respond_with(UpstreamResponse {
        status: 200,
        headers: vec![h("Set-Cookie", "a=b"), h("Connection", "close")],
        body: Vec::new(),
    });
    let resp = env.app.proxy(get(&cookie, "orders", &[])).await.unwrap();
    assert!(resp.headers.is_empty(), "{:?}", resp.headers);
}

/// Upstream lento: `UpstreamTimeout` (504).
#[tokio::test(start_paused = true)]
async fn upstream_lento_es_upstream_timeout() {
    let env = Env::new();
    let cookie = login(&env).await;
    env.ports.upstream().fail_with(UpstreamError::Timeout);
    let r = env.app.proxy(get(&cookie, "orders", &[])).await;
    assert_eq!(r.unwrap_err(), AppError::UpstreamTimeout);
    assert_eq!(AppError::UpstreamTimeout.code(), "upstream_timeout");
}

/// Upstream caido o respuesta demasiado grande: `UpstreamUnavailable` (502), sin detalles.
#[tokio::test(start_paused = true)]
async fn upstream_caido_es_upstream_unavailable() {
    let env = Env::new();
    let cookie = login(&env).await;
    for e in [UpstreamError::Unavailable, UpstreamError::TooLarge] {
        env.ports.upstream().fail_with(e);
        let r = env.app.proxy(get(&cookie, "orders", &[])).await;
        let err = r.unwrap_err();
        assert_eq!(err, AppError::UpstreamUnavailable);
        assert_eq!(err.code(), "upstream_unavailable");
        assert!(!format!("{err:?} {err}").contains("idp.test"));
    }
}

/// Los codigos de error no filtran mensajes internos: son identificadores fijos.
#[test]
fn los_errores_publicos_solo_exponen_codigos_estables() {
    for e in [
        AppError::Unauthorized,
        AppError::Forbidden,
        AppError::Csrf,
        AppError::BadRequest,
        AppError::PayloadTooLarge,
        AppError::UpstreamTimeout,
        AppError::UpstreamUnavailable,
        AppError::Busy,
        AppError::Internal,
    ] {
        assert!(
            e.code().bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "{e:?}"
        );
    }
}
