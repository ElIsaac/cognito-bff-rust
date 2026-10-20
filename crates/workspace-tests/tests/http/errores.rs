//! Formato uniforme de errores (decision 49): `{"error","requestId"}`, `no-store` y
//! `X-Request-ID`.

use application::ports::{SessionRepository, UpstreamError};
use axum::http::{Method, StatusCode};

use crate::support::{Env, Req, assert_error, hash_of};

/// Pone a la sesion con un lease de refresco ajeno vigente y el access token por vencer:
/// la siguiente peticion termina en `Busy`.
async fn forzar_busy(env: &Env, id: &str) {
    env.advance_secs(3600 - 30).await;
    let version = env.ports.sessions().snapshot(&hash_of(id)).unwrap().version;
    let t0 = env.ports.clock().now();
    env.ports
        .sessions()
        .acquire_refresh_lease(
            &hash_of(id),
            version,
            t0,
            t0.saturating_add(std::time::Duration::from_secs(10)),
        )
        .await
        .unwrap();
}

/// Todo error 4xx/5xx tiene exactamente la forma `{"error","requestId"}`, `no-store` y un
/// `X-Request-ID` igual al `requestId`, venga de donde venga.
#[tokio::test(start_paused = true)]
async fn todos_los_errores_tienen_la_misma_forma() {
    let env = Env::con(|c, _| c.proxy_max_body = 1024);
    let id = env.sesion().await;
    let casos: Vec<(&str, crate::support::Resp, StatusCode, &str)> = vec![
        (
            "401",
            env.send(Req::get("/auth/me")).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        ),
        (
            "403",
            env.send(Req::post("/auth/logout").sesion(&id)).await,
            StatusCode::FORBIDDEN,
            "csrf",
        ),
        (
            "404",
            env.send(Req::get("/nada")).await,
            StatusCode::NOT_FOUND,
            "not_found",
        ),
        (
            "405",
            env.send(Req::new(Method::TRACE, "/auth/me")).await,
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
        ),
        (
            "400",
            env.send(Req::get("/api/..%2Fauth").sesion(&id)).await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            "413",
            env.send(Req::post("/api/x").sesion(&id).csrf().cuerpo(vec![0; 2048]))
                .await,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
        ),
        (
            "415",
            env.send(
                Req::post("/auth/account/mfa/preference")
                    .sesion(&id)
                    .csrf()
                    .header("content-type", "text/plain")
                    .cuerpo(b"x".to_vec()),
            )
            .await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ),
    ];
    for (nombre, resp, status, code) in &casos {
        assert_error(resp, *status, code);
        assert!(resp.json()["requestId"].as_str().unwrap().len() >= 16, "{nombre}");
    }

    env.ports.upstream().fail_with(UpstreamError::Timeout);
    assert_error(
        &env.send(Req::get("/api/x").sesion(&id)).await,
        StatusCode::GATEWAY_TIMEOUT,
        "upstream_timeout",
    );
    env.ports.upstream().fail_with(UpstreamError::Unavailable);
    assert_error(
        &env.send(Req::get("/api/x").sesion(&id)).await,
        StatusCode::BAD_GATEWAY,
        "upstream_unavailable",
    );
    env.ports
        .account()
        .fail_next(application::ports::AccountError::TooManyRequests);
    assert_error(
        &env.send(Req::get("/auth/account/mfa").sesion(&id)).await,
        StatusCode::TOO_MANY_REQUESTS,
        "too_many_requests",
    );
}

/// 500 y 403 de `X-Origin-Verify` tambien usan la forma uniforme.
#[tokio::test(start_paused = true)]
async fn errores_de_origen_tienen_la_misma_forma() {
    let env = Env::con_origen();
    assert_error(
        &env.send(Req::get("/auth/me").sin_verify()).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    env.secrets
        .fail_with(Some(application::ports::AdapterError::Permanent));
    assert_error(
        &env.send(Req::get("/auth/me")).await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
    );
}

/// `Busy`: 503 con `Retry-After: 1`, sin llamar al IdP y con la forma uniforme.
#[tokio::test(start_paused = true)]
async fn busy_es_503_con_retry_after() {
    let env = Env::con(|c, _| c.refresh_retry.max_attempts = 1);
    let id = env.sesion().await;
    forzar_busy(&env, &id).await;
    for ruta in ["/auth/me", "/api/orders", "/auth/account/mfa"] {
        let r = env.send(Req::get(ruta).sesion(&id)).await;
        assert_error(&r, StatusCode::SERVICE_UNAVAILABLE, "busy");
        assert_eq!(r.header("retry-after"), Some("1"), "{ruta}");
        assert!(r.set_cookies().is_empty(), "un Busy no borra la sesion: {ruta}");
    }
    assert_eq!(env.ports.idp().refresh_calls(), 0);
    assert_eq!(env.ports.upstream().request_count(), 0);
}

/// Ningun otro error lleva `Retry-After`.
#[tokio::test(start_paused = true)]
async fn solo_busy_lleva_retry_after() {
    let env = Env::new();
    for r in [
        env.send(Req::get("/auth/me")).await,
        env.send(Req::get("/nada")).await,
        env.send(Req::post("/auth/logout")).await,
    ] {
        assert!(r.header("retry-after").is_none());
    }
}

/// Rutas desconocidas: 404 `not_found` con la forma uniforme, tambien bajo `/auth` y `/api`.
#[tokio::test(start_paused = true)]
async fn rutas_desconocidas_son_404() {
    let env = Env::new();
    let id = env.sesion().await;
    for ruta in [
        "/",
        "/nada",
        "/auth",
        "/auth/",
        "/auth/nada",
        "/auth/me/x",
        "/apix",
        "/api",
        "/admin",
        "/.env",
        "/%2e%2e/auth/me",
    ] {
        let r = env.send(Req::get(ruta).sesion(&id)).await;
        assert_error(&r, StatusCode::NOT_FOUND, "not_found");
        assert!(r.set_cookies().is_empty(), "{ruta}");
    }
    assert_eq!(env.ports.upstream().request_count(), 0);
}

/// Un `X-Request-ID` valido se devuelve igual y se reenvia al upstream.
#[tokio::test(start_paused = true)]
async fn request_id_valido_se_respeta_y_se_reenvia() {
    let env = Env::new();
    let id = env.sesion().await;
    let r = env
        .send(
            Req::get("/api/orders")
                .sesion(&id)
                .header("x-request-id", "abc-123_X.y"),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("x-request-id"), Some("abc-123_X.y"));
    let up = env.ports.upstream().requests();
    let reenviado: Vec<&str> = up[0]
        .headers
        .iter()
        .filter(|(k, _)| k == "x-request-id")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(reenviado, ["abc-123_X.y"]);

    let r = env
        .send(Req::get("/nada").header("x-request-id", "mi-id-de-correlacion"))
        .await;
    assert_eq!(r.json()["requestId"], "mi-id-de-correlacion");
    assert_eq!(r.header("x-request-id"), Some("mi-id-de-correlacion"));
}

/// Un `X-Request-ID` invalido (espacios, simbolos, largo, vacio, repetido o no ASCII) se
/// descarta: el BFF genera uno propio de 32 hex y ese es el que ve el upstream. No hay
/// inyeccion de logs ni de cabeceras.
#[tokio::test(start_paused = true)]
async fn request_id_invalido_se_reemplaza() {
    let env = Env::new();
    let id = env.sesion().await;
    let largo = "a".repeat(65);
    let casos: Vec<Vec<&[u8]>> = vec![
        vec![b"a b"],
        vec![b"a;b"],
        vec![b"<script>"],
        vec![b"a/b"],
        vec![b""],
        vec![largo.as_bytes()],
        vec![b"uno", b"dos"],
        vec![b"caf\xc3\xa9"],
        vec![b"a\tb"],
    ];
    for valores in casos {
        let req = valores.iter().fold(Req::get("/api/orders").sesion(&id), |r, v| {
            r.header_bytes("x-request-id", v)
        });
        let r = env.send(req).await;
        assert_eq!(r.status, StatusCode::OK);
        let nuevo = r.header("x-request-id").unwrap().to_owned();
        assert_eq!(nuevo.len(), 32, "{valores:?}");
        assert!(nuevo.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!valores.contains(&nuevo.as_bytes()));
        let up = env.ports.upstream().requests();
        let vistos: Vec<&str> = up
            .last()
            .unwrap()
            .headers
            .iter()
            .filter(|(k, _)| k == "x-request-id")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(vistos, [nuevo.as_str()]);
    }
}

/// Dos peticiones sin `X-Request-ID` reciben ids distintos.
#[tokio::test(start_paused = true)]
async fn los_request_id_generados_son_distintos() {
    let env = Env::new();
    let a = env.send(Req::get("/nada")).await;
    let b = env.send(Req::get("/nada")).await;
    assert_ne!(a.header("x-request-id"), b.header("x-request-id"));
}

/// Toda respuesta de `/auth/*` lleva `Cache-Control: no-store`: redirects, JSON y errores.
#[tokio::test(start_paused = true)]
async fn las_respuestas_de_auth_son_no_store() {
    let env = Env::new();
    let id = env.sesion().await;
    let ini = env.iniciar(None).await;
    let respuestas = vec![
        ("login", env.send(Req::get("/auth/login")).await),
        (
            "login autenticado",
            env.send(Req::get("/auth/login").sesion(&id)).await,
        ),
        ("callback ok", env.callback(&ini, &env.emitir_code(&ini)).await),
        ("callback error", env.send(Req::get("/auth/callback")).await),
        ("me", env.send(Req::get("/auth/me").sesion(&id)).await),
        ("me 401", env.send(Req::get("/auth/me")).await),
        (
            "ws-ticket",
            env.send(Req::post("/auth/ws-ticket").csrf().sesion(&id)).await,
        ),
        ("mfa", env.send(Req::get("/auth/account/mfa").sesion(&id)).await),
        (
            "associate",
            env.send(Req::post("/auth/account/mfa/totp/associate").csrf().sesion(&id))
                .await,
        ),
        (
            "verify",
            env.send(
                Req::post("/auth/account/mfa/totp/verify")
                    .csrf()
                    .sesion(&id)
                    .json(r#"{"code":"123456"}"#),
            )
            .await,
        ),
        ("csrf", env.send(Req::post("/auth/logout").sesion(&id)).await),
        (
            "logout",
            env.send(Req::post("/auth/logout").csrf().sesion(&id)).await,
        ),
    ];
    for (nombre, r) in respuestas {
        assert_eq!(r.header("cache-control"), Some("no-store"), "{nombre}");
    }
}
