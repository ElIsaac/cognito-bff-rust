//! Fugas de informacion por `tracing` en los flujos HTTP: nada secreto sale a los logs.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use application::ports::{AccountError, AdapterError, UpstreamError};
use axum::http::Method;
use in_memory::{FAKE_PASSWORD, FAKE_TOTP_CODE, FAKE_TOTP_SECRET};
use tracing::field::{Field, Visit};
use tracing::{Event, Metadata, Subscriber, span};
use tracing_core::span::Current;

use crate::support::{Env, PENDING_COOKIE, Req, SECRETO_ACTUAL, SECRETO_PREVIO, hash_of, query_param};

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

/// Subscriber minimo que guarda cada evento y cada span (con todos sus campos, en formato
/// `Debug`) como una linea de texto.
#[derive(Clone, Default)]
struct Captura {
    lineas: Arc<Mutex<Vec<String>>>,
    siguiente: Arc<AtomicU64>,
    /// Metadatos de cada span y pila de spans abiertos, para que `Span::current()` (y con el
    /// `record` desde los casos de uso) funcione como con un subscriber de verdad.
    spans: Arc<Mutex<HashMap<u64, &'static Metadata<'static>>>>,
    pila: Arc<Mutex<Vec<u64>>>,
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
        let id = self.siguiente.fetch_add(1, Ordering::Relaxed) + 1;
        self.spans.lock().unwrap().insert(id, attrs.metadata());
        span::Id::from_u64(id)
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

    fn enter(&self, id: &span::Id) {
        self.pila.lock().unwrap().push(id.into_u64());
    }

    fn exit(&self, _: &span::Id) {
        self.pila.lock().unwrap().pop();
    }

    fn current_span(&self) -> Current {
        let Some(id) = self.pila.lock().unwrap().last().copied() else {
            return Current::none();
        };
        let meta = self.spans.lock().unwrap().get(&id).copied();
        meta.map_or_else(Current::none, |m| Current::new(span::Id::from_u64(id), m))
    }
}

/// Instala `captura` como subscriber del hilo. Con un unico `Dispatch` vivo en el proceso,
/// `tracing` cachea el interes de cada callsite contra ese subscriber y otro test en paralelo
/// puede dejarlo desactivado; con dos, el interes se consulta en cada evento.
fn capturar(captura: &Captura) -> (tracing::Dispatch, tracing::dispatcher::DefaultGuard) {
    let otro = tracing::Dispatch::new(Captura::default());
    let guard = tracing::dispatcher::set_default(&tracing::Dispatch::new(captura.clone()));
    (otro, guard)
}

/// Valores sensibles observados durante los flujos.
#[derive(Default)]
struct Secretos(Vec<(&'static str, String)>);

impl Secretos {
    fn anota(&mut self, nombre: &'static str, valor: impl Into<String>) {
        let valor = valor.into();
        assert!(valor.len() >= 6, "{nombre} demasiado corto para buscarlo");
        self.0.push((nombre, valor));
    }

    fn anota_sesion(&mut self, env: &Env, id: &str) {
        self.anota("session id", id);
        let s = env.ports.sessions().snapshot(&hash_of(id)).unwrap();
        self.anota("access token", s.tokens.access.expose_secret());
        self.anota("refresh token", s.tokens.refresh.expose_secret());
    }
}

fn assert_sin_secretos(lineas: &[String], secretos: &Secretos) {
    for (nombre, valor) in &secretos.0 {
        if let Some(l) = lineas.iter().find(|l| l.contains(valor.as_str())) {
            panic!("fuga de {nombre} en tracing: {l}");
        }
    }
}

/// Fuga por logs: se ejecutan por HTTP todos los flujos (login, callback, me, boleto WS,
/// cuenta, proxy, logout y los errores de cada uno: CSRF, origen, cookies hostiles, upstream,
/// Cognito, `Busy`) con un subscriber que captura todo, en todos los niveles. Ningun id de
/// sesion o pending, `state`, `nonce`, `code`, token, boleto, secreto TOTP, codigo TOTP,
/// contrasena ni secreto de origen debe aparecer.
#[tokio::test(start_paused = true)]
async fn tracing_no_contiene_secretos_en_ningun_flujo_http() {
    let captura = Captura::default();
    let _guard = capturar(&captura);
    let env = Env::con(|c, h| {
        h.origin_verify_secret = Some(crate::support::SECRET_NAME.to_owned());
        c.refresh_retry.max_attempts = 1;
    });
    env.ports.idp().set_rotate_refresh(true);
    env.secrets.set_previous(Some(SECRETO_PREVIO));
    let mut secretos = Secretos::default();
    // El `sub` solo puede salir como huella.
    secretos.anota("sub del usuario", crate::support::SUB);
    secretos.anota("secreto de origen", SECRETO_ACTUAL);
    secretos.anota("secreto de origen previo", SECRETO_PREVIO);
    secretos.anota("secreto TOTP", FAKE_TOTP_SECRET);
    secretos.anota("codigo TOTP", FAKE_TOTP_CODE);
    secretos.anota("contrasena inicial", FAKE_PASSWORD);
    secretos.anota("contrasena nueva", "Nueva-clave-456");
    secretos.anota("contrasena previa mala", "incorrecta-123");

    // Login feliz por HTTP, con todos los secretos del flujo anotados.
    let ini = env.iniciar(Some("returnTo=%2Fdashboard")).await;
    let pending = env
        .ports
        .pending()
        .snapshot(&domain::PendingId::parse(&ini.pending).unwrap().hash())
        .expect("pending guardado");
    secretos.anota("pending id", ini.pending.clone());
    secretos.anota("state", ini.state.clone());
    secretos.anota("nonce", query_param(&ini.url, "nonce"));
    secretos.anota("code_verifier", pending.code_verifier.expose_secret());
    secretos.anota("code_challenge", query_param(&ini.url, "code_challenge"));
    secretos.anota("url de autorizacion", ini.url.clone());
    let code = env.emitir_code(&ini);
    secretos.anota("code", code.clone());
    let cb = env.callback(&ini, &code).await;
    let id = cb.cookie_fijada(crate::support::SESSION_COOKIE).unwrap();
    secretos.anota_sesion(&env, &id);

    // Lectura, boleto, cuenta.
    env.send(
        Req::get("/auth/me")
            .sesion(&id)
            .header("traceparent", &format!("00-{TRACE_ID}-00f067aa0ba902b7-01")),
    )
    .await;
    let t = env.send(Req::post("/auth/ws-ticket").csrf().sesion(&id)).await;
    secretos.anota("boleto ws", t.json()["ticket"].as_str().unwrap());
    let json = |ruta: &str, cuerpo: &str| Req::post(ruta).csrf().sesion(&id).json(cuerpo);
    env.send(Req::get("/auth/account/mfa").sesion(&id)).await;
    env.send(Req::post("/auth/account/mfa/totp/associate").csrf().sesion(&id))
        .await;
    env.send(json("/auth/account/mfa/totp/verify", r#"{"code":"000000"}"#))
        .await;
    env.send(json(
        "/auth/account/mfa/totp/verify",
        r#"{"code":"123456","deviceName":"Telefono"}"#,
    ))
    .await;
    env.send(json("/auth/account/mfa/preference", r#"{"totp":false}"#))
        .await;
    env.send(json(
        "/auth/account/change-password",
        r#"{"previousPassword":"incorrecta-123","proposedPassword":"Nueva-clave-456"}"#, // gitleaks:allow (valores de prueba)
    ))
    .await;
    env.send(json(
        "/auth/account/change-password",
        r#"{"previousPassword":"Inicial-123","proposedPassword":"Nueva-clave-456"}"#,
    ))
    .await;
    env.ports.account().fail_next(AccountError::TooManyRequests);
    env.send(Req::get("/auth/account/mfa").sesion(&id)).await;
    env.ports
        .account()
        .fail_next(AccountError::Adapter(AdapterError::Permanent));
    env.send(Req::get("/auth/account/mfa").sesion(&id)).await;

    // Proxy: feliz, con cabeceras del atacante y con cada error.
    secretos.anota("authorization del atacante", "Bearer token-del-atacante-xyz");
    env.send(
        Req::get("/api/orders?q=1")
            .sesion(&id)
            .header("authorization", "Bearer token-del-atacante-xyz")
            .header("x-request-id", "correlacion-123"),
    )
    .await;
    env.send(Req::get("/api/..%2Fauth%2Fme").sesion(&id)).await;
    env.send(
        Req::post("/api/x")
            .sesion(&id)
            .csrf()
            .cuerpo(vec![0; crate::support::MAX_BODY + 1]),
    )
    .await;
    for e in [
        UpstreamError::Timeout,
        UpstreamError::Unavailable,
        UpstreamError::TooLarge,
    ] {
        env.ports.upstream().fail_with(e);
        env.send(Req::get("/api/orders").sesion(&id)).await;
    }

    // Rechazos del borde: CSRF, origen, cookies hostiles y rutas desconocidas.
    env.send(Req::post("/auth/logout").sesion(&id)).await;
    env.send(
        Req::post("/auth/ws-ticket")
            .sesion(&id)
            .csrf()
            .header("origin", "https://evil.com"),
    )
    .await;
    secretos.anota("valor de origen incorrecto", "valor-de-origen-incorrecto");
    env.send(
        Req::get("/auth/me")
            .sesion(&id)
            .sin_verify()
            .header("x-origin-verify", "valor-de-origen-incorrecto"),
    )
    .await;
    env.send(Req::get("/auth/me").sesion(&id).sin_verify()).await;
    env.secrets.fail_with(Some(AdapterError::Transient));
    env.send(Req::get("/auth/me").sesion(&id)).await;
    env.secrets.fail_with(None);
    let hostil = "H".repeat(43);
    secretos.anota("cookie hostil", hostil.clone());
    env.send(Req::get("/auth/me").sesion(&hostil)).await;
    env.send(Req::new(Method::TRACE, "/auth/me").sesion(&id)).await;
    env.send(Req::get("/nada").sesion(&id)).await;

    // Errores de login: pending ausente, state ajeno, error del proveedor con descripcion,
    // replay y code invalido.
    secretos.anota("error_description", "descripcion-controlada-por-atacante");
    for variante in 0..5 {
        let ini = env.iniciar(None).await;
        secretos.anota("pending id", ini.pending.clone());
        secretos.anota("state", ini.state.clone());
        secretos.anota("nonce", query_param(&ini.url, "nonce"));
        let code = env.emitir_code(&ini);
        secretos.anota("code", code.clone());
        let pend = |r: Req| r.cookie(PENDING_COOKIE, &ini.pending);
        match variante {
            0 => {
                env.send(Req::get(&format!(
                    "/auth/callback?code={code}&state={}",
                    ini.state
                )))
                .await;
            }
            1 => {
                env.send(pend(Req::get(&format!("/auth/callback?code={code}&state=ajeno"))))
                    .await;
            }
            2 => {
                let uri = format!(
                    "/auth/callback?error=access_denied&error_description=descripcion-controlada-por-atacante&state={}",
                    ini.state
                );
                env.send(pend(Req::get(&uri))).await;
            }
            3 => {
                env.callback(&ini, &code).await;
                env.callback(&ini, &code).await;
            }
            _ => {
                env.callback(&ini, "code-inventado-por-el-atacante").await;
            }
        }
    }

    // Refresh con rotacion y Busy.
    env.advance_secs(3600 - 30).await;
    env.send(Req::get("/auth/me").sesion(&id)).await;
    secretos.anota_sesion(&env, &id);
    env.advance_secs(3600 - 30).await;
    let version = env.ports.sessions().snapshot(&hash_of(&id)).unwrap().version;
    let t0 = env.ports.clock().now();
    {
        use application::ports::SessionRepository;
        env.ports
            .sessions()
            .acquire_refresh_lease(
                &hash_of(&id),
                version,
                t0,
                t0.saturating_add(std::time::Duration::from_secs(10)),
            )
            .await
            .unwrap();
    }
    env.send(Req::get("/auth/me").sesion(&id)).await;
    env.advance_secs(11).await;

    // Logout y uso posterior.
    env.send(Req::post("/auth/logout").csrf().sesion(&id)).await;
    env.send(Req::get("/auth/me").sesion(&id)).await;
    env.send(Req::get("/auth/login").sesion(&id)).await;

    let lineas = captura.todo();
    assert!(
        lineas.len() > 40,
        "la captura no funciona: {} lineas",
        lineas.len()
    );
    for esperado in [
        "peticion",
        "login completado",
        "CSRF rechazado",
        "X-Origin-Verify ausente",
        "login fallido",
        "upstream fallo",
    ] {
        assert!(
            lineas.iter().any(|l| l.contains(esperado)),
            "falta {esperado:?} en la captura"
        );
    }
    assert_sin_secretos(&lineas, &secretos);

    // Si, en cambio, la huella del `sub` y el `trace_id` del `traceparent` valido.
    let sub_hash = domain::Subject::new(crate::support::SUB.to_owned())
        .unwrap()
        .log_hash();
    assert_eq!(sub_hash.len(), 16);
    assert!(
        lineas
            .iter()
            .any(|l| l.starts_with("SPAN-RECORD") && l.contains(&format!("sub_hash=\"{sub_hash}\""))),
        "falta sub_hash en los spans"
    );
    assert!(
        lineas
            .iter()
            .any(|l| l.starts_with("SPAN ") && l.contains(&format!("trace_id={TRACE_ID:?}"))),
        "falta trace_id en los spans"
    );
}
