//! `/auth/account/*` (decision 48): MFA con TOTP y cambio de contrasena.

use application::ports::AccountError;
use axum::http::StatusCode;
use in_memory::{FAKE_PASSWORD, FAKE_TOTP_CODE, FAKE_TOTP_SECRET};

use crate::support::{Env, Req, Resp, SESSION_COOKIE, assert_error};

const MFA: &str = "/auth/account/mfa";
const ASSOCIATE: &str = "/auth/account/mfa/totp/associate";
const VERIFY: &str = "/auth/account/mfa/totp/verify";
const PREFERENCE: &str = "/auth/account/mfa/preference";
const PASSWORD: &str = "/auth/account/change-password";
const NUEVA: &str = "Nueva-clave-456";

fn cuerpo_password(previa: &str, nueva: &str) -> String {
    format!(r#"{{"previousPassword":"{previa}","proposedPassword":"{nueva}"}}"#)
}

fn verify_con(code: &str) -> String {
    format!(r#"{{"code":"{code}"}}"#)
}

async fn post(env: &Env, id: &str, ruta: &str, cuerpo: &str) -> Resp {
    env.send(Req::post(ruta).sesion(id).csrf().json(cuerpo)).await
}

async fn estado(env: &Env, id: &str) -> String {
    let r = env.send(Req::get(MFA).sesion(id)).await;
    assert_eq!(r.status, StatusCode::OK);
    r.json()["totp"].as_str().unwrap().to_owned()
}

/// El estado inicial del MFA es `disabled` y la respuesta es solo `{"totp"}`.
#[tokio::test(start_paused = true)]
async fn el_estado_inicial_es_disabled() {
    let env = Env::new();
    let id = env.sesion().await;
    let r = env.send(Req::get(MFA).sesion(&id)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json(), serde_json::json!({ "totp": "disabled" }));
    assert_eq!(r.header("cache-control"), Some("no-store"));
}

/// El secreto TOTP sale una vez, sin cache, y solo con el campo `secret`.
#[tokio::test(start_paused = true)]
async fn associate_devuelve_el_secreto_sin_cache() {
    let env = Env::new();
    let id = env.sesion().await;
    let r = env.send(Req::post(ASSOCIATE).sesion(&id).csrf()).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json(), serde_json::json!({ "secret": FAKE_TOTP_SECRET }));
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert!(r.header("etag").is_none());
}

/// Codigo equivocado: 400 `code_mismatch` y el MFA sigue desactivado; con el correcto: 204 y
/// queda `enabled`.
#[tokio::test(start_paused = true)]
async fn verify_con_codigo_equivocado_y_correcto() {
    let env = Env::new();
    let id = env.sesion().await;
    post(&env, &id, ASSOCIATE, "").await;
    let r = post(&env, &id, VERIFY, &verify_con("000000")).await;
    assert_error(&r, StatusCode::BAD_REQUEST, "code_mismatch");
    assert_eq!(estado(&env, &id).await, "disabled");

    let r = post(
        &env,
        &id,
        VERIFY,
        &format!(r#"{{"code":"{FAKE_TOTP_CODE}","deviceName":"Mi telefono"}}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(r.body.is_empty());
    assert_eq!(estado(&env, &id).await, "enabled");
    assert!(env.ports.account().totp_enabled());
}

/// Verificar sin haber asociado: 400 `mfa_setup_invalid`.
#[tokio::test(start_paused = true)]
async fn verify_antes_de_associate_es_mfa_setup_invalid() {
    let env = Env::new();
    let id = env.sesion().await;
    let r = post(&env, &id, VERIFY, &verify_con(FAKE_TOTP_CODE)).await;
    assert_error(&r, StatusCode::BAD_REQUEST, "mfa_setup_invalid");
    assert_eq!(estado(&env, &id).await, "disabled");
    let r = post(&env, &id, PREFERENCE, r#"{"totp":true}"#).await;
    assert_error(&r, StatusCode::BAD_REQUEST, "mfa_setup_invalid");
}

/// La preferencia `{"totp":false}` desactiva el MFA.
#[tokio::test(start_paused = true)]
async fn la_preferencia_false_desactiva_el_totp() {
    let env = Env::new();
    let id = env.sesion().await;
    post(&env, &id, ASSOCIATE, "").await;
    post(&env, &id, VERIFY, &verify_con(FAKE_TOTP_CODE)).await;
    assert_eq!(estado(&env, &id).await, "enabled");
    let r = post(&env, &id, PREFERENCE, r#"{"totp":false}"#).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(estado(&env, &id).await, "disabled");
    let r = post(&env, &id, PREFERENCE, r#"{"totp":true}"#).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(estado(&env, &id).await, "enabled");
}

/// Contrasena previa equivocada: 400 `not_authorized` y no cambia; con datos validos: 204.
#[tokio::test(start_paused = true)]
async fn change_password_con_previa_equivocada_y_valida() {
    let env = Env::new();
    let id = env.sesion().await;
    let r = post(&env, &id, PASSWORD, &cuerpo_password("incorrecta-123", NUEVA)).await;
    assert_error(&r, StatusCode::BAD_REQUEST, "not_authorized");
    assert_eq!(env.ports.account().password(), FAKE_PASSWORD);

    let r = post(&env, &id, PASSWORD, &cuerpo_password(FAKE_PASSWORD, "corta")).await;
    assert_error(&r, StatusCode::BAD_REQUEST, "invalid_password");
    assert_eq!(env.ports.account().password(), FAKE_PASSWORD);

    let r = post(&env, &id, PASSWORD, &cuerpo_password(FAKE_PASSWORD, NUEVA)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(r.body.is_empty());
    assert_eq!(env.ports.account().password(), NUEVA);
}

/// Las rutas con cuerpo solo aceptan `application/json`: cualquier otro tipo (o ninguno) es
/// 415 y no se llama a Cognito.
#[tokio::test(start_paused = true)]
async fn content_type_no_json_es_415() {
    let env = Env::new();
    let id = env.sesion().await;
    let rutas = [
        (VERIFY, verify_con(FAKE_TOTP_CODE)),
        (PREFERENCE, r#"{"totp":false}"#.to_owned()),
        (PASSWORD, cuerpo_password(FAKE_PASSWORD, NUEVA)),
    ];
    for (ruta, cuerpo) in &rutas {
        for ct in [
            Some("text/plain"),
            Some("application/x-www-form-urlencoded"),
            Some("application/jsonx"),
            Some("text/json"),
            Some("multipart/form-data"),
            None,
        ] {
            let mut req = Req::post(ruta)
                .sesion(&id)
                .csrf()
                .cuerpo(cuerpo.as_bytes().to_vec());
            if let Some(ct) = ct {
                req = req.header("content-type", ct);
            }
            let r = env.send(req).await;
            assert_error(&r, StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
        }
    }
    assert!(env.ports.account().calls().is_empty());
    assert_eq!(env.ports.account().password(), FAKE_PASSWORD);

    let r = env
        .send(
            Req::post(PREFERENCE)
                .sesion(&id)
                .csrf()
                .header("content-type", "Application/JSON; charset=utf-8")
                .cuerpo(br#"{"totp":false}"#.to_vec()),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
}

/// Cuerpo de mas de 4 KiB: 413 y no se llama a Cognito.
#[tokio::test(start_paused = true)]
async fn cuerpo_de_mas_de_4_kib_es_413() {
    let env = Env::new();
    let id = env.sesion().await;
    let relleno = "a".repeat(4096);
    let cuerpos = [
        (VERIFY, format!(r#"{{"code":"123456","deviceName":"{relleno}"}}"#)),
        (PREFERENCE, format!(r#"{{"totp":true,"x":"{relleno}"}}"#)),
        (PASSWORD, cuerpo_password(&relleno, NUEVA)),
        (PREFERENCE, " ".repeat(4097)),
    ];
    for (ruta, cuerpo) in cuerpos {
        let r = post(&env, &id, ruta, &cuerpo).await;
        assert_error(&r, StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
    }
    assert!(env.ports.account().calls().is_empty());
}

/// Campos desconocidos, JSON roto, tipos equivocados y campos faltantes: 400 `bad_request`.
#[tokio::test(start_paused = true)]
async fn cuerpos_malformados_son_400() {
    let env = Env::new();
    let id = env.sesion().await;
    let casos = [
        (VERIFY, r#"{"code":"123456","extra":1}"#),
        (VERIFY, r#"{"code":"123456","deviceName":"x","admin":true}"#),
        (VERIFY, r"{}"),
        (VERIFY, r#"{"code":123456}"#),
        (VERIFY, r#"{"code":null}"#),
        (VERIFY, r#"{"code":"123456""#),
        (VERIFY, r""),
        (PREFERENCE, r#"{"totp":false,"x":1}"#),
        (PREFERENCE, r#"{"totp":"false"}"#),
        (PREFERENCE, r"{}"),
        (PREFERENCE, r#"{"TOTP":false}"#),
        (
            PASSWORD,
            r#"{"previousPassword":"a","proposedPassword":"b","x":1}"#,
        ),
        (PASSWORD, r#"{"previousPassword":"a"}"#),
        (PASSWORD, r#"{"previous_password":"a","proposed_password":"b"}"#),
        (PASSWORD, r#"{"previousPassword":"","proposedPassword":"b"}"#),
        (PASSWORD, r#"{"previousPassword":"a","proposedPassword":""}"#),
        (
            PASSWORD,
            r#"{"previousPassword":"a\u0000b","proposedPassword":"c"}"#,
        ),
    ];
    for (ruta, cuerpo) in casos {
        let r = post(&env, &id, ruta, cuerpo).await;
        assert_eq!(r.json()["error"], "bad_request", "{ruta} {cuerpo}");
        assert_error(&r, StatusCode::BAD_REQUEST, "bad_request");
    }
    assert!(
        env.ports.account().calls().is_empty(),
        "nada de esto debe llegar a Cognito"
    );
}

/// Codigos TOTP que no son exactamente 6 digitos ASCII: 400 sin llamar a Cognito.
#[tokio::test(start_paused = true)]
async fn codigos_totp_invalidos_son_400() {
    let env = Env::new();
    let id = env.sesion().await;
    let invalidos = [
        "12345",
        "1234567",
        "abcdef",
        "12345a",
        " 12345",
        "12345 ",
        "",
        "12-456",
        "１２３４５６",
        "+12345",
        "1e5555",
    ];
    for codigo in invalidos {
        let r = post(&env, &id, VERIFY, &verify_con(codigo)).await;
        assert_error(&r, StatusCode::BAD_REQUEST, "bad_request");
    }
    let r = post(
        &env,
        &id,
        VERIFY,
        &format!(r#"{{"code":"123456","deviceName":"{}"}}"#, "n".repeat(65)),
    )
    .await;
    assert_error(&r, StatusCode::BAD_REQUEST, "bad_request");
    let r = post(&env, &id, VERIFY, r#"{"code":"123456","deviceName":"a\nb"}"#).await;
    assert_error(&r, StatusCode::BAD_REQUEST, "bad_request");
    assert!(env.ports.account().calls().is_empty());
}

/// Limite de intentos de Cognito: 429 `too_many_requests`.
#[tokio::test(start_paused = true)]
async fn too_many_requests_es_429() {
    let env = Env::new();
    let id = env.sesion().await;
    env.ports.account().fail_next(AccountError::TooManyRequests);
    let r = post(&env, &id, VERIFY, &verify_con(FAKE_TOTP_CODE)).await;
    assert_error(&r, StatusCode::TOO_MANY_REQUESTS, "too_many_requests");
    env.ports.account().fail_next(AccountError::TooManyRequests);
    let r = env.send(Req::get(MFA).sesion(&id)).await;
    assert_error(&r, StatusCode::TOO_MANY_REQUESTS, "too_many_requests");
    // Un fallo es de una sola llamada.
    assert_eq!(estado(&env, &id).await, "disabled");
}

/// Los demas rechazos de Cognito salen con su codigo de lista blanca; los fallos del
/// adaptador no filtran detalles (502 / 500).
#[tokio::test(start_paused = true)]
async fn rechazos_y_fallos_de_cognito_tienen_codigos_estables() {
    use application::ports::AdapterError;
    let env = Env::new();
    let id = env.sesion().await;
    let casos = [
        (AccountError::CodeExpired, StatusCode::BAD_REQUEST, "code_expired"),
        (
            AccountError::NotAuthorized,
            StatusCode::BAD_REQUEST,
            "not_authorized",
        ),
        (
            AccountError::InvalidPassword,
            StatusCode::BAD_REQUEST,
            "invalid_password",
        ),
        (
            AccountError::MfaSetupInvalid,
            StatusCode::BAD_REQUEST,
            "mfa_setup_invalid",
        ),
        (
            AccountError::Adapter(AdapterError::Transient),
            StatusCode::BAD_GATEWAY,
            "upstream_unavailable",
        ),
        (
            AccountError::Adapter(AdapterError::Permanent),
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
        ),
    ];
    for (e, status, code) in casos {
        env.ports.account().fail_next(e);
        let r = env.send(Req::get(MFA).sesion(&id)).await;
        assert_error(&r, status, code);
    }
}

/// Sin sesion ninguna operacion de cuenta funciona: 401 y no se llama a Cognito.
#[tokio::test(start_paused = true)]
async fn sin_sesion_todo_es_401() {
    let env = Env::new();
    let id = "Q".repeat(43);
    let r = env.send(Req::get(MFA)).await;
    assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    assert!(r.borra_cookie(SESSION_COOKIE));
    for (ruta, cuerpo) in [
        (ASSOCIATE, ""),
        (VERIFY, r#"{"code":"123456"}"#),
        (PREFERENCE, r#"{"totp":false}"#),
        (PASSWORD, r#"{"previousPassword":"a","proposedPassword":"b"}"#),
    ] {
        let r = env.send(Req::post(ruta).csrf().json(cuerpo)).await;
        assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
        let r = env.send(Req::post(ruta).csrf().sesion(&id).json(cuerpo)).await;
        assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
        assert!(r.borra_cookie(SESSION_COOKIE));
    }
    assert!(env.ports.account().calls().is_empty());
}

/// Toda llamada a Cognito usa el access token de la sesion (nunca uno del cliente), tambien
/// despues de un refresh.
#[tokio::test(start_paused = true)]
async fn toda_llamada_de_cuenta_usa_el_access_token_de_la_sesion() {
    let env = Env::new();
    let id = env.sesion().await;
    let access = env.access_de(&id);
    let ataque = |r: Req| {
        r.header("authorization", "Bearer del-cliente")
            .header("x-amz-access-token", "del-cliente")
    };

    env.send(ataque(Req::get(MFA).sesion(&id))).await;
    env.send(ataque(Req::post(ASSOCIATE).sesion(&id).csrf())).await;
    env.send(ataque(
        Req::post(VERIFY)
            .sesion(&id)
            .csrf()
            .json(&verify_con(FAKE_TOTP_CODE)),
    ))
    .await;
    env.send(ataque(
        Req::post(PREFERENCE).sesion(&id).csrf().json(r#"{"totp":false}"#),
    ))
    .await;
    env.send(ataque(
        Req::post(PASSWORD)
            .sesion(&id)
            .csrf()
            .json(&cuerpo_password(FAKE_PASSWORD, NUEVA)),
    ))
    .await;

    let llamadas = env.ports.account().calls();
    let ops: Vec<&str> = llamadas.iter().map(|(op, _)| *op).collect();
    assert_eq!(
        ops,
        [
            "mfa_status",
            "associate_totp",
            "verify_totp",
            "set_totp",
            "set_totp",
            "change_password"
        ]
    );
    assert!(llamadas.iter().all(|(_, token)| *token == access), "{llamadas:?}");

    env.advance_secs(3600 - 30).await;
    env.send(Req::get(MFA).sesion(&id)).await;
    let nuevo = env.access_de(&id);
    assert_ne!(nuevo, access);
    assert_eq!(env.ports.account().calls().last().unwrap().1, nuevo);
}
