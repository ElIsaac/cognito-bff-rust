//! Proxy `/api/*` (§6.5) sobre HTTP: cabeceras, ruta, cuerpo, errores y respuesta.

use application::ports::{Method as UMethod, UpstreamError, UpstreamResponse};
use axum::http::{Method, StatusCode};

use crate::support::{Env, MAX_BODY, Req, SESSION_COOKIE, assert_error};

fn h(k: &str, v: &str) -> (String, String) {
    (k.to_owned(), v.to_owned())
}

/// Suplantacion hacia el upstream y smuggling: ninguna cabecera prohibida llega; el BFF pone
/// su propio `Authorization`.
#[tokio::test(start_paused = true)]
async fn cabeceras_prohibidas_no_llegan_al_upstream() {
    for env in [Env::new(), Env::con_origen()] {
        let id = env.sesion().await;
        let prohibidas = [
            "host",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "forwarded",
            "x-real-ip",
            "referer",
            "connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "proxy-authorization",
            "proxy-connection",
            "x-amzn-trace-id",
        ];
        let mut req = Req::post("/api/orders?a=1")
            .sesion(&id)
            .csrf()
            .sin_verify()
            .header("origin", crate::support::ORIGIN);
        for n in prohibidas {
            req = req.header(n, "valor-del-atacante");
        }
        let r = env
            .send(
                req.header("x-origin-verify", crate::support::SECRETO_ACTUAL)
                    .header("authorization", "Bearer token-del-atacante")
                    .header("cookie", "otra=cookie-del-atacante")
                    .header("accept", "application/json")
                    .header("traceparent", "00-aaaa-bbbb-01")
                    .json("{}"),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK);

        let reqs = env.ports.upstream().requests();
        assert_eq!(reqs.len(), 1);
        let up = &reqs[0];
        let mut nombres: Vec<&str> = up.headers.iter().map(|(k, _)| k.as_str()).collect();
        nombres.sort_unstable();
        assert_eq!(nombres, ["accept", "content-type", "traceparent", "x-request-id"]);
        assert!(
            up.headers.iter().all(|(k, _)| k != "origin"),
            "origin llego al upstream"
        );
        for (k, v) in &up.headers {
            assert!(!v.contains("atacante"), "{k}: {v}");
            assert!(!v.contains(&id), "{k} lleva la cookie de sesion");
            assert!(!v.contains("origen-actual"), "{k} lleva el secreto de origen");
        }
        assert_eq!(up.method, UMethod::Post);
        assert_eq!(up.path.as_str(), "orders");
        assert_eq!(up.query.as_deref(), Some("a=1"));
        assert_eq!(up.body, b"{}");
    }
}

/// El bearer es el access token de la sesion, nunca el que mande el cliente.
#[tokio::test(start_paused = true)]
async fn el_bearer_es_el_access_token_de_la_sesion() {
    let env = Env::new();
    let id = env.sesion().await;
    let access = env.access_de(&id);
    let r = env
        .send(
            Req::get("/api/orders")
                .sesion(&id)
                .header("authorization", "Bearer del-cliente")
                .header("x-amzn-oidc-accesstoken", "otro"),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let reqs = env.ports.upstream().requests();
    assert_eq!(reqs[0].bearer.expose_secret(), access);
    assert!(!r.text().contains(&access));
}

/// El bearer sigue siendo el de la sesion despues de un refresh (no uno viejo).
#[tokio::test(start_paused = true)]
async fn el_bearer_es_el_refrescado_tras_vencer() {
    let env = Env::new();
    let id = env.sesion().await;
    let viejo = env.access_de(&id);
    env.advance_secs(3600 - 30).await;
    let r = env.send(Req::get("/api/orders").sesion(&id)).await;
    assert_eq!(r.status, StatusCode::OK);
    let nuevo = env.access_de(&id);
    assert_ne!(nuevo, viejo);
    assert_eq!(env.ports.upstream().requests()[0].bearer.expose_secret(), nuevo);
}

/// Path traversal y rutas hostiles (§9.2): 400, sin llegar al upstream.
#[tokio::test(start_paused = true)]
async fn rutas_hostiles_dan_400_sin_llegar_al_upstream() {
    let env = Env::new();
    let id = env.sesion().await;
    let largo = "a".repeat(5000);
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
        "a%5cb",
        "a%2fb",
        "a%00b",
        "a%252e",
        "a%0D%0AHost:%20evil",
        "%zz",
        "..",
        ".",
        "./",
        "a/..",
        &largo,
    ];
    for ruta in rutas {
        let r = env.send(Req::get(&format!("/api/{ruta}")).sesion(&id)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "ruta {ruta:?}");
        assert_error(&r, StatusCode::BAD_REQUEST, "bad_request");
    }
    assert_eq!(env.ports.upstream().request_count(), 0);
    assert_eq!(env.ports.idp().refresh_calls(), 0);
}

/// El host del upstream no se puede cambiar: ni con una URL en la ruta ni con la forma
/// absoluta de la peticion; el upstream solo recibe una ruta relativa.
#[tokio::test(start_paused = true)]
async fn el_host_no_se_puede_cambiar() {
    let env = Env::new();
    let id = env.sesion().await;
    for ruta in [
        "/api/https://evil",
        "/api/http://evil.com/x",
        "/api//evil.com/x",
        "/api/%2F%2Fevil.com",
    ] {
        let r = env.send(Req::get(ruta).sesion(&id)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{ruta}: {}", r.text());
    }
    assert_eq!(env.ports.upstream().request_count(), 0);

    let r = env
        .send(
            Req::get("http://evil.com/api/orders")
                .sesion(&id)
                .header("host", "evil.com"),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let reqs = env.ports.upstream().requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].path.as_str(), "orders");
    assert!(reqs[0].headers.iter().all(|(k, _)| k != "host"));
}

/// `/api` sin ruta o con ruta vacia no llega al proxy.
#[tokio::test(start_paused = true)]
async fn api_sin_ruta_es_404() {
    let env = Env::new();
    let id = env.sesion().await;
    for ruta in ["/api", "/api/"] {
        let r = env.send(Req::get(ruta).sesion(&id)).await;
        assert_error(&r, StatusCode::NOT_FOUND, "not_found");
    }
    assert_eq!(env.ports.upstream().request_count(), 0);
}

/// Rutas normales con apariencia rara se reenvian tal cual (sin decodificar ni normalizar).
#[tokio::test(start_paused = true)]
async fn rutas_normales_se_reenvian_tal_cual() {
    let env = Env::new();
    let id = env.sesion().await;
    let rutas = [
        "orders",
        "orders/42",
        "a-b_c.d/e~f",
        "orders/",
        "file.v1.json",
        "%7Euser",
    ];
    for ruta in rutas {
        let r = env.send(Req::get(&format!("/api/{ruta}")).sesion(&id)).await;
        assert_eq!(r.status, StatusCode::OK, "{ruta}");
    }
    let enviadas: Vec<String> = env
        .ports
        .upstream()
        .requests()
        .iter()
        .map(|r| r.path.as_str().to_owned())
        .collect();
    assert_eq!(enviadas, rutas);
}

/// El upstream no puede plantar cookies ni inyectar cabeceras de CORS/HSTS/hop-by-hop; el
/// status y el cuerpo pasan intactos.
#[tokio::test(start_paused = true)]
async fn set_cookie_del_upstream_se_elimina() {
    let env = Env::new();
    let id = env.sesion().await;
    env.ports.upstream().respond_with(UpstreamResponse {
        status: 201,
        headers: vec![
            h("set-cookie", &format!("{SESSION_COOKIE}=fijada; Path=/")),
            h("Set-Cookie", "otra=x"),
            h("set-cookie2", "x=y"),
            h("connection", "close"),
            h("keep-alive", "timeout=5"),
            h("transfer-encoding", "chunked"),
            h("upgrade", "websocket"),
            h("strict-transport-security", "max-age=0"),
            h("access-control-allow-origin", "https://evil.com"),
            h("access-control-allow-credentials", "true"),
            h("content-type", "application/json"),
            h("etag", "\"abc\""),
        ],
        body: br#"{"ok":true}"#.to_vec(),
    });
    let r = env.send(Req::get("/api/orders").sesion(&id)).await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert_eq!(r.body, br#"{"ok":true}"#);
    assert!(r.set_cookies().is_empty(), "{:?}", r.set_cookies());
    let mut nombres: Vec<&str> = r.headers.keys().map(axum::http::HeaderName::as_str).collect();
    nombres.sort_unstable();
    // `content-length` lo recalcula el router a partir del cuerpo; el del upstream se descarta.
    assert_eq!(
        nombres,
        [
            "cache-control",
            "content-length",
            "content-type",
            "etag",
            "x-request-id"
        ]
    );
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("content-length"), Some("11"));
    assert_eq!(r.header("etag"), Some("\"abc\""));
}

/// Dec. 8: todo `/api/*` sale con `Cache-Control: no-store`, venga lo que venga del upstream,
/// y sin las cabeceras internas ni las que el upstream declara en `Connection`.
#[tokio::test(start_paused = true)]
async fn api_siempre_sale_con_no_store() {
    let env = Env::con_origen();
    let id = env.sesion().await;
    env.ports.upstream().respond_with(UpstreamResponse {
        status: 200,
        headers: vec![
            h("cache-control", "public, max-age=31536000, immutable"),
            h("Expires", "Thu, 01 Jan 2099 00:00:00 GMT"),
            h("pragma", "cache"),
            h("server", "Kestrel"),
            h("x-amzn-requestid", "abc"),
            h("x-amzn-trace-id", "Root=1-abc"),
            h("apigw-requestid", "Zx="),
            h("connection", "x-interna"),
            h("x-interna", "1"),
            h("content-type", "application/json"),
        ],
        body: b"{}".to_vec(),
    });
    let r = env.send(Req::get("/api/orders").sesion(&id)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.headers.get_all("cache-control").iter().count(), 1);
    for prohibida in [
        "expires",
        "pragma",
        "server",
        "x-amzn-requestid",
        "x-amzn-trace-id",
        "apigw-requestid",
        "connection",
        "x-interna",
    ] {
        assert!(r.header(prohibida).is_none(), "{prohibida}");
    }
    assert_eq!(r.header("content-type"), Some("application/json"));

    // Tambien las respuestas que no vienen del upstream.
    let casos = [
        env.send(Req::get("/api/orders")).await,
        env.send(Req::get("/api/orders").sin_verify().sesion(&id)).await,
        env.send(Req::get("/api/").sesion(&id)).await,
        env.send(Req::get("/api/%2e%2e/x").sesion(&id)).await,
        env.send(Req::post("/api/orders").sesion(&id)).await,
    ];
    for r in casos {
        assert_eq!(r.header("cache-control"), Some("no-store"), "{}", r.status);
    }
    env.ports.upstream().fail_with(UpstreamError::Timeout);
    let r = env.send(Req::get("/api/orders").sesion(&id)).await;
    assert_eq!(r.header("cache-control"), Some("no-store"));
}

async fn assert_cuerpo_rechazado(
    env: &Env,
    id: &str,
    con_content_length: bool,
    tam: usize,
    declarado: Option<usize>,
) {
    let mut req = Req::post("/api/upload").sesion(id).csrf().cuerpo(vec![b'x'; tam]);
    if con_content_length {
        req = req.header("content-length", &declarado.unwrap_or(tam).to_string());
    }
    let r = env.send(req).await;
    assert_error(&r, StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
}

/// DoS por cuerpo enorme: mas de `proxy_max_body` es 413 con y sin `Content-Length`, y no
/// llega al upstream; justo en el limite pasa.
#[tokio::test(start_paused = true)]
async fn cuerpo_mayor_al_limite_es_413() {
    let env = Env::con(|c, _| c.proxy_max_body = 1024);
    let id = env.sesion().await;
    assert_cuerpo_rechazado(&env, &id, false, 1025, None).await;
    assert_cuerpo_rechazado(&env, &id, true, 1025, None).await;
    // Content-Length mentiroso hacia abajo: el limite se aplica al cuerpo real.
    assert_cuerpo_rechazado(&env, &id, true, 1025, Some(10)).await;
    // Content-Length declarado enorme con cuerpo chico: se rechaza por lo declarado.
    assert_cuerpo_rechazado(&env, &id, true, 10, Some(10_000_000)).await;
    assert_eq!(env.ports.upstream().request_count(), 0);

    let r = env
        .send(
            Req::post("/api/upload")
                .sesion(&id)
                .csrf()
                .cuerpo(vec![b'x'; 1024]),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = env
        .send(
            Req::post("/api/upload")
                .sesion(&id)
                .csrf()
                .header("content-length", "1024")
                .cuerpo(vec![b'x'; 1024]),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(env.ports.upstream().request_count(), 2);
}

/// El limite por defecto de la config de pruebas (1 MiB) tambien se aplica.
#[tokio::test(start_paused = true)]
async fn limite_por_defecto_de_un_mebibyte() {
    let env = Env::new();
    let id = env.sesion().await;
    assert_cuerpo_rechazado(&env, &id, false, MAX_BODY + 1, None).await;
    assert_eq!(env.ports.upstream().request_count(), 0);
}

/// Upstream lento: 504 `upstream_timeout`; caido o con respuesta demasiado grande: 502
/// `upstream_unavailable`. El cuerpo nunca trae detalles internos.
#[tokio::test(start_paused = true)]
async fn timeout_y_caida_del_upstream_no_filtran_detalles() {
    let env = Env::new();
    let id = env.sesion().await;
    let casos = [
        (
            UpstreamError::Timeout,
            StatusCode::GATEWAY_TIMEOUT,
            "upstream_timeout",
        ),
        (
            UpstreamError::Unavailable,
            StatusCode::BAD_GATEWAY,
            "upstream_unavailable",
        ),
        (
            UpstreamError::TooLarge,
            StatusCode::BAD_GATEWAY,
            "upstream_unavailable",
        ),
    ];
    for (err, status, code) in casos {
        env.ports.upstream().fail_with(err);
        let r = env.send(Req::get("/api/orders?secreto=1").sesion(&id)).await;
        assert_error(&r, status, code);
        let cuerpo = r.text();
        for filtrado in [
            "Timeout",
            "Unavailable",
            "TooLarge",
            "idp.test",
            "orders",
            "secreto",
            "Bearer",
            "panicked",
        ] {
            assert!(!cuerpo.contains(filtrado), "{filtrado} en {cuerpo}");
        }
    }
}

/// La query viaja cruda (sin decodificar ni reordenar), incluidos duplicados y vacios.
#[tokio::test(start_paused = true)]
async fn la_query_pasa_cruda() {
    let env = Env::new();
    let id = env.sesion().await;
    let query = "a=1&b=%2F%20x&a=2&=&z&q=%E2%9C%93&r=a+b";
    let r = env
        .send(Req::get(&format!("/api/orders?{query}")).sesion(&id))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = env.send(Req::get("/api/orders").sesion(&id)).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = env.send(Req::get("/api/orders?").sesion(&id)).await;
    assert_eq!(r.status, StatusCode::OK);
    let reqs = env.ports.upstream().requests();
    assert_eq!(reqs[0].query.as_deref(), Some(query));
    assert_eq!(reqs[1].query, None);
    assert_eq!(reqs[2].query, None, "query vacia no se reenvia");
}

/// Status y cuerpo del upstream pasan tal cual: un 404 o un 500 del upstream no se
/// reescriben con el formato de errores del BFF.
#[tokio::test(start_paused = true)]
async fn status_y_cuerpo_del_upstream_pasan() {
    let env = Env::new();
    let id = env.sesion().await;
    for (status, cuerpo) in [
        (200u16, "hola"),
        (404, r#"{"mensaje":"no existe"}"#),
        (409, "conflicto"),
        (500, "boom interno del upstream"),
    ] {
        env.ports.upstream().respond_with(UpstreamResponse {
            status,
            headers: vec![h("content-type", "application/json")],
            body: cuerpo.as_bytes().to_vec(),
        });
        let r = env.send(Req::get("/api/orders/9").sesion(&id)).await;
        assert_eq!(r.status.as_u16(), status);
        assert_eq!(r.text(), cuerpo);
        assert_eq!(r.header("content-type"), Some("application/json"));
        assert!(r.header("x-request-id").is_some());
    }
    env.ports.upstream().respond_with(UpstreamResponse {
        status: 204,
        headers: vec![],
        body: vec![],
    });
    let r = env
        .send(Req::new(Method::DELETE, "/api/orders/9").sesion(&id).csrf())
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(r.body.is_empty());
}

/// Metodo y cuerpo llegan intactos para cada metodo que cambia estado.
#[tokio::test(start_paused = true)]
async fn metodo_y_cuerpo_llegan_intactos() {
    let env = Env::new();
    let id = env.sesion().await;
    for (m, esperado) in [
        (Method::POST, UMethod::Post),
        (Method::PUT, UMethod::Put),
        (Method::PATCH, UMethod::Patch),
        (Method::DELETE, UMethod::Delete),
        (Method::GET, UMethod::Get),
    ] {
        let r = env
            .send(
                Req::new(m.clone(), "/api/x")
                    .sesion(&id)
                    .csrf()
                    .json(r#"{"k":"v"}"#),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{m}");
        let reqs = env.ports.upstream().requests();
        let ultima = reqs.last().unwrap();
        assert_eq!(ultima.method, esperado);
        assert_eq!(ultima.body, br#"{"k":"v"}"#);
    }
}

/// Sin sesion no se reenvia nada.
#[tokio::test(start_paused = true)]
async fn sin_sesion_el_proxy_da_401() {
    let env = Env::new();
    let r = env.send(Req::get("/api/orders")).await;
    assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    assert!(r.borra_cookie(SESSION_COOKIE));
    assert_eq!(env.ports.upstream().request_count(), 0);
}
