//! Fugas de informacion: nada secreto sale por `tracing` ni por `Debug`.

use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use application::ports::{AdapterError, IdpError, Method, UpstreamError};
use application::{CallbackParams, ProxyCall, StartLoginOutcome};
use domain::{PendingId, WsTicketId};
use tracing::field::{Field, Visit};
use tracing::{Event, Metadata, Subscriber, span};

use crate::common::{Env, callback, config, hash_of, query_param, secs, user};

/// Subscriber minimo que guarda cada evento y cada span (con todos sus campos, en formato
/// `Debug`) como una linea de texto.
#[derive(Clone, Default)]
struct Captura {
    lineas: Arc<Mutex<Vec<String>>>,
    siguiente: Arc<AtomicU64>,
}

struct Campos<'a>(&'a mut String);

impl Visit for Campos<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

impl Captura {
    fn push(&self, linea: String) {
        self.lineas.lock().unwrap().push(linea);
    }

    fn todo(&self) -> Vec<String> {
        self.lineas.lock().unwrap().clone()
    }
}

impl Subscriber for Captura {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attrs: &span::Attributes<'_>) -> span::Id {
        let mut s = format!("SPAN {} {}", attrs.metadata().target(), attrs.metadata().name());
        attrs.record(&mut Campos(&mut s));
        self.push(s);
        span::Id::from_u64(self.siguiente.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _: &span::Id, values: &span::Record<'_>) {
        let mut s = String::from("SPAN-RECORD");
        values.record(&mut Campos(&mut s));
        self.push(s);
    }

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let m = event.metadata();
        let mut s = format!("{} {} {}", m.level(), m.target(), m.name());
        event.record(&mut Campos(&mut s));
        self.push(s);
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

/// Valores sensibles observados durante los flujos.
#[derive(Default)]
struct Secretos(Vec<(&'static str, String)>);

impl Secretos {
    fn anota(&mut self, nombre: &'static str, valor: impl Into<String>) {
        let valor = valor.into();
        assert!(valor.len() >= 16, "{nombre} demasiado corto para buscarlo");
        self.0.push((nombre, valor));
    }

    fn anota_sesion(&mut self, env: &Env, cookie: &str) {
        self.anota("session id", cookie);
        let s = env.ports.sessions().snapshot(&hash_of(cookie)).unwrap();
        self.anota("access token", s.tokens.access.expose_secret());
        self.anota("refresh token", s.tokens.refresh.expose_secret());
    }
}

/// Login con todos los secretos del flujo anotados.
async fn login_anotado(env: &Env, secretos: &mut Secretos) -> String {
    let outcome = env.app.start_login(None, Some("/dashboard")).await.unwrap();
    let StartLoginOutcome::Redirect {
        authorization_url,
        pending_id,
        ..
    } = outcome
    else {
        panic!("se esperaba redireccion");
    };
    let state = query_param(&authorization_url, "state");
    let pending = env
        .ports
        .pending()
        .snapshot(&pending_id.hash())
        .expect("pending guardado");
    secretos.anota("pending id", pending_id.expose_secret());
    secretos.anota("state", state.clone());
    secretos.anota("nonce", pending.nonce.expose_secret());
    secretos.anota("code_verifier", pending.code_verifier.expose_secret());
    secretos.anota("code_challenge", pending.code_verifier.challenge().as_str());
    secretos.anota("url de autorizacion", authorization_url);

    let code = env.ports.idp().issue_code(&state, user());
    secretos.anota("code", code.clone());
    let done = env
        .app
        .complete_login(Some(&pending_id.expose_secret()), callback(&code, &state), None)
        .await
        .unwrap();
    let cookie = done.session_id.expose_secret();
    secretos.anota_sesion(env, &cookie);
    cookie
}

/// Instala `captura` como subscriber del hilo. Con un unico `Dispatch` vivo en el proceso,
/// `tracing` cachea el interes de cada callsite contra ese subscriber y otro test en paralelo
/// puede dejarlo desactivado; con dos, el interes se consulta en cada evento.
fn capturar(captura: &Captura) -> (tracing::Dispatch, tracing::dispatcher::DefaultGuard) {
    let otro = tracing::Dispatch::new(Captura::default());
    let guard = tracing::dispatcher::set_default(&tracing::Dispatch::new(captura.clone()));
    (otro, guard)
}

fn assert_sin_secretos(lineas: &[String], secretos: &Secretos) {
    for (nombre, valor) in &secretos.0 {
        if let Some(l) = lineas.iter().find(|l| l.contains(valor.as_str())) {
            panic!("fuga de {nombre} en tracing: {l}");
        }
    }
}

/// Fuga por logs: se ejecutan todos los flujos (login, refresh, rotacion, logout, proxy,
/// boleto WS y los errores de cada uno) con un subscriber que captura todo, en todos los
/// niveles. Ningun identificador de sesion/pending, `state`, `nonce`, `code_verifier`,
/// `code`, token ni boleto debe aparecer en la salida.
#[tokio::test(start_paused = true)]
async fn tracing_no_contiene_secretos_en_ningun_flujo() {
    let captura = Captura::default();
    let _guard = capturar(&captura);
    let env = Env::new();
    env.ports.idp().set_rotate_refresh(true);
    let mut secretos = Secretos::default();

    // Login feliz y lectura.
    let cookie = login_anotado(&env, &mut secretos).await;
    env.app.current_user(Some(&cookie)).await.unwrap();

    // Refresh con rotacion.
    env.advance_secs(3600 - 30).await;
    env.app.current_user(Some(&cookie)).await.unwrap();
    secretos.anota_sesion(&env, &cookie);

    // Boleto WS.
    let ticket = env.app.issue_ws_ticket(Some(&cookie)).await.unwrap();
    secretos.anota("ticket ws", ticket.ticket.expose_secret());

    // Proxy: feliz y con cada error.
    let headers = [("accept".to_owned(), "*/*".to_owned())];
    let llamada = |path| ProxyCall {
        session_cookie: Some(&cookie),
        method: Method::Get,
        path,
        query: Some("q=1"),
        headers: &headers,
        body: Vec::new(),
    };
    env.app.proxy(llamada("orders")).await.unwrap();
    env.app.proxy(llamada("../auth/me")).await.unwrap_err();
    for e in [
        UpstreamError::Timeout,
        UpstreamError::Unavailable,
        UpstreamError::TooLarge,
    ] {
        env.ports.upstream().fail_with(e);
        env.app.proxy(llamada("orders")).await.unwrap_err();
    }

    // Errores de login: state ajeno, error del proveedor, pending expirado, nonce distinto.
    for variante in 0..4 {
        let outcome = env.app.start_login(None, None).await.unwrap();
        let StartLoginOutcome::Redirect {
            authorization_url,
            pending_id,
            ..
        } = outcome
        else {
            panic!("redireccion");
        };
        let state = query_param(&authorization_url, "state");
        let nonce = query_param(&authorization_url, "nonce");
        secretos.anota("pending id", pending_id.expose_secret());
        secretos.anota("state", state.clone());
        secretos.anota("nonce", nonce);
        let code = match variante {
            3 => env
                .ports
                .idp()
                .issue_code_with_nonce(&state, user(), &"n".repeat(43)),
            _ => env.ports.idp().issue_code(&state, user()),
        };
        secretos.anota("code", code.clone());
        let params = match variante {
            0 => callback(&code, &domain::State::from_bytes([3; 32]).expose_secret()),
            1 => CallbackParams {
                code: None,
                state: Some(state.clone()),
                error: Some("access_denied".to_owned()),
            },
            2 => {
                env.advance_secs(700).await;
                callback(&code, &state)
            }
            _ => callback(&code, &state),
        };
        env.app
            .complete_login(Some(&pending_id.expose_secret()), params, None)
            .await
            .unwrap_err();
    }

    // Errores de refresh: transitorio con access valido y invalid_grant.
    let cookie2 = login_anotado(&env, &mut secretos).await;
    env.advance_secs(3600 - 30).await;
    env.ports
        .idp()
        .fail_refresh(IdpError::Adapter(AdapterError::Transient), 1);
    env.app.current_user(Some(&cookie2)).await.unwrap();
    env.ports.idp().fail_refresh(IdpError::InvalidGrant, 1);
    env.app.current_user(Some(&cookie2)).await.unwrap_err();

    // Cookies basura, expiracion y logout.
    env.app.current_user(Some("basura")).await.unwrap_err();
    env.app.logout(Some(&cookie)).await.unwrap();
    env.app.logout(Some(&cookie)).await.unwrap();
    env.app.current_user(Some(&cookie)).await.unwrap_err();
    let cookie3 = login_anotado(&env, &mut secretos).await;
    env.advance_secs(13 * 3600).await;
    env.app.current_user(Some(&cookie3)).await.unwrap_err();
    env.app.issue_ws_ticket(Some(&cookie3)).await.unwrap_err();

    let lineas = captura.todo();
    assert!(lineas.len() > 8, "la captura no funciona: {lineas:?}");
    assert!(lineas.iter().any(|l| l.contains("login completado")));
    assert!(lineas.iter().any(|l| l.contains("logout")));
    assert_sin_secretos(&lineas, &secretos);
}

/// Un test de control del propio detector: si un secreto se registrara, se detectaria.
#[tokio::test(start_paused = true)]
async fn el_detector_de_fugas_detecta_una_fuga() {
    let captura = Captura::default();
    let _guard = capturar(&captura);
    tracing::info!(valor = %"secreto-que-no-deberia-salir-1234", "mensaje");
    let mut s = Secretos::default();
    s.anota("control", "secreto-que-no-deberia-salir-1234");
    let lineas = captura.todo();
    let r = std::panic::catch_unwind(|| assert_sin_secretos(&lineas, &s));
    assert!(r.is_err());
}

/// `Debug` de los tipos con secretos no los imprime: `Session`, `PendingAuth`, `TokenSet`,
/// `WsTicket`, `UserInfo` no llevan tokens, `state`, `nonce`, verifier ni ids.
#[tokio::test(start_paused = true)]
async fn debug_de_los_tipos_con_secretos_esta_redactado() {
    let env = Env::new();
    let mut secretos = Secretos::default();
    let p = env.app.start_login(None, None).await.unwrap();
    let StartLoginOutcome::Redirect { pending_id, .. } = p else {
        panic!("redireccion");
    };
    let pending = env.ports.pending().snapshot(&pending_id.hash()).unwrap();
    secretos.anota("state", pending.state.expose_secret());
    secretos.anota("nonce", pending.nonce.expose_secret());
    secretos.anota("code_verifier", pending.code_verifier.expose_secret());
    secretos.anota("pending id", pending_id.expose_secret());

    let cookie = login_anotado(&env, &mut secretos).await;
    let session = env.ports.sessions().snapshot(&hash_of(&cookie)).unwrap();
    let ticket = env.app.issue_ws_ticket(Some(&cookie)).await.unwrap();
    secretos.anota("ticket ws", ticket.ticket.expose_secret());
    let ws = env.ports.tickets().snapshot(&ticket.ticket.hash()).unwrap();

    let impresos = [
        ("Session", format!("{session:?}")),
        ("Session {:#?}", format!("{session:#?}")),
        ("PendingAuth", format!("{pending:?}")),
        ("TokenSet", format!("{:?}", session.tokens)),
        ("WsTicket", format!("{ws:?}")),
        ("PendingId", format!("{pending_id:?}")),
        ("WsTicketId", format!("{:?}", ticket.ticket)),
        (
            "SessionId",
            format!("{:?}", domain::SessionId::parse(&cookie).unwrap()),
        ),
        (
            "CompletedLogin",
            format!("{:?}", PendingId::parse(&pending_id.expose_secret()).unwrap()),
        ),
        (
            "WsTicketId::from_bytes",
            format!("{:?}", WsTicketId::from_bytes([1; 32])),
        ),
    ];
    for (nombre, texto) in &impresos {
        for (secreto, valor) in &secretos.0 {
            assert!(
                !texto.contains(valor.as_str()),
                "Debug de {nombre} imprime {secreto}: {texto}"
            );
        }
    }
    assert!(impresos[0].1.contains("[REDACTED]"));
    assert!(impresos[2].1.contains("[REDACTED]"));
    assert!(impresos[3].1.contains("[REDACTED]"));
}

/// `Debug` de `AppConfig` (que se podria registrar al arrancar) no contiene secretos: solo
/// origen publico, politicas y nombre de cabecera.
#[test]
fn debug_de_app_config_no_lleva_secretos() {
    let texto = format!("{:?}", config());
    assert!(texto.contains("https://app.example.com"));
    for prohibido in ["secret", "password", "token", "key"] {
        assert!(!texto.to_lowercase().contains(prohibido), "{texto}");
    }
}

/// Los tipos de resultado de los casos de uso que viajan hasta la capa HTTP tampoco deben
/// imprimir secretos: `CompletedLogin` (id de sesion) y `IssuedWsTicket` (boleto).
#[tokio::test(start_paused = true)]
async fn debug_de_resultados_de_casos_de_uso_no_filtra() {
    let env = Env::new();
    let mut secretos = Secretos::default();
    let outcome = env.app.start_login(None, None).await.unwrap();
    let StartLoginOutcome::Redirect {
        authorization_url,
        pending_id,
        ..
    } = outcome
    else {
        panic!("redireccion");
    };
    let state = query_param(&authorization_url, "state");
    let code = env.ports.idp().issue_code(&state, user());
    let done = env
        .app
        .complete_login(Some(&pending_id.expose_secret()), callback(&code, &state), None)
        .await
        .unwrap();
    secretos.anota("session id", done.session_id.expose_secret());
    let cookie = done.session_id.expose_secret();
    let ticket = env.app.issue_ws_ticket(Some(&cookie)).await.unwrap();
    secretos.anota("ticket ws", ticket.ticket.expose_secret());
    for texto in [format!("{done:?}"), format!("{ticket:?}")] {
        for (nombre, valor) in &secretos.0 {
            assert!(!texto.contains(valor.as_str()), "{nombre} en {texto}");
        }
    }
    let _ = secs(0);
}

/// `StartLoginOutcome::Redirect` lleva la URL de autorizacion (con `state`, `nonce` y
/// `code_challenge`) en un `String`: su `Debug` los imprime. Si alguien lo registra con `{:?}`
/// los valores terminan en los logs.
#[tokio::test(start_paused = true)]
async fn debug_de_start_login_outcome_no_imprime_state_ni_nonce() {
    let env = Env::new();
    let outcome = env.app.start_login(None, None).await.unwrap();
    let StartLoginOutcome::Redirect {
        authorization_url, ..
    } = &outcome
    else {
        panic!("redireccion");
    };
    let state = query_param(authorization_url, "state");
    let nonce = query_param(authorization_url, "nonce");
    let texto = format!("{outcome:?}");
    assert!(!texto.contains(&state) && !texto.contains(&nonce), "{texto}");
}

/// `CallbackParams` conserva `code` y `state` como `String`: su `Debug` derivado los imprime.
#[test]
fn debug_de_callback_params_no_imprime_code_ni_state() {
    let p = CallbackParams {
        code: Some("codigo-secreto-0123456789".to_owned()),
        state: Some("state-secreto-0123456789".to_owned()),
        error: None,
    };
    let texto = format!("{p:?}");
    assert!(!texto.contains("secreto"), "{texto}");
}

/// `ProxyCall` guarda la cookie de sesion (`&str`) y las cabeceras del cliente (incluidos
/// `cookie` y `authorization`) en claro: su `Debug` derivado imprime el id de sesion.
#[test]
fn debug_de_proxy_call_no_imprime_la_cookie_de_sesion() {
    let headers = [("authorization".to_owned(), "Bearer abc123secreto".to_owned())];
    let call = ProxyCall {
        session_cookie: Some("id-de-sesion-secreto-0123456789"),
        method: Method::Get,
        path: "x",
        query: None,
        headers: &headers,
        body: Vec::new(),
    };
    let texto = format!("{call:?}");
    assert!(!texto.contains("secreto"), "{texto}");
}
