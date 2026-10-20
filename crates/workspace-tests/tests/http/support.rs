//! Entorno comun: router real, fakes en memoria, constructor de peticiones y flujo de login
//! completo por HTTP.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use application::ports::{AdapterError, SecretProvider, SecretValue, SecretVersions};
use application::{App, AppConfig, RefreshRetry};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header};
use domain::{
    Email, GroupName, PendingPolicy, SessionId, SessionPolicy, SessionPolicyConfig, Subject, UserInfo,
    WsTicketPolicy,
};
use http_axum::HttpConfig;
use in_memory::MemPorts;
use tower::ServiceExt;

pub const ORIGIN: &str = "https://app.example.com";
pub const CSRF_HEADER: &str = "x-requested-with";
pub const SESSION_COOKIE: &str = "__Host-bff_session";
pub const PENDING_COOKIE: &str = http_axum::PENDING_COOKIE;
pub const MAX_BODY: usize = 1024 * 1024;
pub const TENANT: &str = "tenant-42";
pub const SECRET_NAME: &str = "origin-verify-secret";
pub const SECRETO_ACTUAL: &str = "origen-actual-0123456789abcdef";
pub const SECRETO_PREVIO: &str = "origen-previo-fedcba9876543210";

// ---------------------------------------------------------------------------------------
// SecretProvider de prueba
// ---------------------------------------------------------------------------------------

#[derive(Debug)]
struct EstadoSecreto {
    current: String,
    previous: Option<String>,
    error: Option<AdapterError>,
}

/// `SecretProvider` con valor actual, valor anterior opcional, contador de lecturas y un
/// error inyectable.
#[derive(Debug)]
pub struct FakeSecrets {
    estado: Mutex<EstadoSecreto>,
    lecturas: AtomicUsize,
}

impl FakeSecrets {
    pub fn new(current: &str, previous: Option<&str>) -> Self {
        Self {
            estado: Mutex::new(EstadoSecreto {
                current: current.to_owned(),
                previous: previous.map(str::to_owned),
                error: None,
            }),
            lecturas: AtomicUsize::new(0),
        }
    }

    pub fn set_previous(&self, v: Option<&str>) {
        self.estado.lock().unwrap().previous = v.map(str::to_owned);
    }

    pub fn fail_with(&self, e: Option<AdapterError>) {
        self.estado.lock().unwrap().error = e;
    }

    pub fn lecturas(&self) -> usize {
        self.lecturas.load(Ordering::SeqCst)
    }
}

// El fake es sincrono por dentro pero implementa un puerto asincrono.
#[allow(clippy::unused_async_trait_impl)]
impl SecretProvider for FakeSecrets {
    async fn get(&self, _name: &str) -> Result<SecretVersions, AdapterError> {
        self.lecturas.fetch_add(1, Ordering::SeqCst);
        let s = self.estado.lock().unwrap();
        if let Some(e) = s.error {
            return Err(e);
        }
        Ok(SecretVersions {
            current: SecretValue::new(s.current.clone()),
            previous: s.previous.clone().map(SecretValue::new),
        })
    }

    fn invalidate(&self, _name: &str) {}
}

// ---------------------------------------------------------------------------------------
// Peticiones y respuestas
// ---------------------------------------------------------------------------------------

/// Peticion en construccion. Las cabeceras se agregan (no reemplazan), asi se arman las
/// repetidas.
pub struct Req {
    method: Method,
    uri: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    sin_verify: bool,
}

impl Req {
    pub fn new(method: Method, uri: &str) -> Self {
        Self {
            method,
            uri: uri.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
            sin_verify: false,
        }
    }

    pub fn get(uri: &str) -> Self {
        Self::new(Method::GET, uri)
    }

    pub fn post(uri: &str) -> Self {
        Self::new(Method::POST, uri)
    }

    pub fn header(self, k: &str, v: &str) -> Self {
        self.header_bytes(k, v.as_bytes())
    }

    pub fn header_bytes(mut self, k: &str, v: &[u8]) -> Self {
        self.headers.push((k.to_owned(), v.to_vec()));
        self
    }

    pub fn cookie(self, name: &str, value: &str) -> Self {
        self.header("cookie", &format!("{name}={value}"))
    }

    pub fn sesion(self, id: &str) -> Self {
        self.cookie(SESSION_COOKIE, id)
    }

    /// Cabecera anti-CSRF de las llamadas legitimas del front.
    pub fn csrf(self) -> Self {
        self.header(CSRF_HEADER, "XMLHttpRequest")
    }

    pub fn json(mut self, body: &str) -> Self {
        self.body = body.as_bytes().to_vec();
        self.header("content-type", "application/json")
    }

    pub fn cuerpo(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// No agrega el `X-Origin-Verify` automatico del entorno.
    pub fn sin_verify(mut self) -> Self {
        self.sin_verify = true;
        self
    }

    fn build(self, verify: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method(self.method).uri(self.uri);
        for (k, v) in self.headers {
            b = b.header(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_bytes(&v).unwrap(),
            );
        }
        if let (Some(v), false) = (verify, self.sin_verify) {
            b = b.header("x-origin-verify", v);
        }
        b.body(Body::from(self.body)).unwrap()
    }
}

pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|v| v.to_str().unwrap())
    }

    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }

    pub fn location(&self) -> &str {
        self.header("location").expect("falta Location")
    }

    pub fn text(&self) -> String {
        String::from_utf8(self.body.clone()).unwrap()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("no es JSON ({e}): {}", self.text()))
    }

    /// Valor no vacio de la cookie `name` fijada por esta respuesta.
    pub fn cookie_fijada(&self, name: &str) -> Option<String> {
        self.set_cookies().iter().find_map(|c| {
            let v = c.strip_prefix(&format!("{name}="))?.split(';').next()?;
            (!v.is_empty()).then(|| v.to_owned())
        })
    }

    /// `true` si la respuesta borra la cookie `name`.
    pub fn borra_cookie(&self, name: &str) -> bool {
        self.set_cookies()
            .iter()
            .any(|c| c.starts_with(&format!("{name}=;")) && c.contains("Max-Age=0"))
    }
}

// ---------------------------------------------------------------------------------------
// Entorno
// ---------------------------------------------------------------------------------------

pub fn config() -> AppConfig {
    let session = SessionPolicy::new(SessionPolicyConfig {
        absolute_ttl: Duration::from_hours(7 * 24),
        idle_ttl: Duration::from_hours(12),
        ..SessionPolicyConfig::default()
    })
    .unwrap();
    AppConfig {
        public_origin: ORIGIN.to_owned(),
        session,
        pending: PendingPolicy::default(),
        ws_ticket: WsTicketPolicy::default(),
        refresh_retry: RefreshRetry::default(),
        proxy_max_body: MAX_BODY,
        csrf_header: CSRF_HEADER.to_owned(),
    }
}

pub fn http_config() -> HttpConfig {
    HttpConfig {
        session_cookie: SESSION_COOKIE.to_owned(),
        auth_error_path: "/".to_owned(),
        origin_verify_secret: None,
    }
}

pub fn user() -> UserInfo {
    UserInfo::new(
        Subject::new("user-1".to_owned()).unwrap(),
        Some(Email::new("ana@example.com".to_owned()).unwrap()),
        Some("Ana".to_owned()),
        vec![
            GroupName::new("admins".to_owned()).unwrap(),
            GroupName::new("ventas".to_owned()).unwrap(),
        ],
    )
    .with_attributes([("custom:tenant_id".to_owned(), TENANT.to_owned())])
}

pub fn hash_of(cookie: &str) -> domain::IdHash {
    SessionId::parse(cookie).unwrap().hash()
}

pub struct Env {
    pub ports: Arc<MemPorts>,
    pub secrets: Arc<FakeSecrets>,
    router: Router,
    /// Valor que `send` agrega como `X-Origin-Verify` si la peticion no lo evita.
    verify: Option<String>,
}

/// Login en curso tal como lo ve el navegador.
pub struct Inicio {
    pub pending: String,
    pub state: String,
    pub url: String,
    pub resp: Resp,
}

/// Login completado por HTTP.
pub struct Sesion {
    pub id: String,
    pub callback: Resp,
}

impl Env {
    /// Debe llamarse dentro de un runtime de tokio (el reloj toma el instante actual).
    pub fn new() -> Self {
        Self::con(|_, _| {})
    }

    pub fn con(tweak: impl FnOnce(&mut AppConfig, &mut HttpConfig)) -> Self {
        let mut cfg = config();
        let mut http = http_config();
        tweak(&mut cfg, &mut http);
        let verify = http
            .origin_verify_secret
            .is_some()
            .then(|| SECRETO_ACTUAL.to_owned());
        let ports = Arc::new(MemPorts::new());
        let secrets = Arc::new(FakeSecrets::new(SECRETO_ACTUAL, None));
        let app = App::new(Arc::clone(&ports), cfg);
        let router = http_axum::router(app, http, Arc::clone(&secrets)).unwrap();
        Self {
            ports,
            secrets,
            router,
            verify,
        }
    }

    /// Entorno con `X-Origin-Verify` exigido; `send` agrega el valor actual por defecto.
    pub fn con_origen() -> Self {
        Self::con(|_, h| h.origin_verify_secret = Some(SECRET_NAME.to_owned()))
    }

    pub async fn advance_secs(&self, s: u64) {
        self.ports.clock().advance(Duration::from_secs(s)).await;
    }

    pub async fn send(&self, req: Req) -> Resp {
        let resp = self
            .router
            .clone()
            .oneshot(req.build(self.verify.as_deref()))
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX).await.unwrap().to_vec();
        Resp {
            status: parts.status,
            headers: parts.headers,
            body,
        }
    }

    /// `GET /auth/login` con la query cruda (`returnTo=...`).
    pub async fn iniciar(&self, query: Option<&str>) -> Inicio {
        let uri = query.map_or_else(|| "/auth/login".to_owned(), |q| format!("/auth/login?{q}"));
        let resp = self.send(Req::get(&uri)).await;
        assert_eq!(resp.status, StatusCode::SEE_OTHER, "login");
        let url = resp.location().to_owned();
        Inicio {
            pending: resp.cookie_fijada(PENDING_COOKIE).expect("cookie pending"),
            state: query_param(&url, "state"),
            url,
            resp,
        }
    }

    /// Code que el IdP de prueba entrega al usuario autenticado para este login.
    pub fn emitir_code(&self, ini: &Inicio) -> String {
        self.ports.idp().issue_code(&ini.state, user())
    }

    pub async fn callback(&self, ini: &Inicio, code: &str) -> Resp {
        let uri = format!("/auth/callback?code={code}&state={}", ini.state);
        self.send(Req::get(&uri).cookie(PENDING_COOKIE, &ini.pending))
            .await
    }

    /// Login completo por HTTP (`/auth/login` y `/auth/callback`).
    pub async fn login(&self, query: Option<&str>) -> Sesion {
        let ini = self.iniciar(query).await;
        let code = self.emitir_code(&ini);
        let callback = self.callback(&ini, &code).await;
        let id = callback
            .cookie_fijada(SESSION_COOKIE)
            .unwrap_or_else(|| panic!("el callback no fijo sesion: {}", callback.location()));
        Sesion { id, callback }
    }

    /// Login con un `returnTo` cualquiera y devuelve solo la cookie de sesion.
    pub async fn sesion(&self) -> String {
        self.login(Some("returnTo=%2Fdashboard")).await.id
    }

    pub fn access_de(&self, cookie: &str) -> String {
        self.ports
            .sessions()
            .snapshot(&hash_of(cookie))
            .unwrap()
            .tokens
            .access
            .expose_secret()
            .to_owned()
    }
}

pub fn query_param(url: &str, key: &str) -> String {
    let query = url.split_once('?').unwrap().1;
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
        .unwrap()
        .to_owned()
}

/// Codifica en porcentaje todo salvo los no reservados (para armar queries con valores
/// hostiles).
pub fn enc(s: &str) -> String {
    use std::fmt::Write;
    s.bytes().fold(String::new(), |mut out, b| {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
        out
    })
}

/// Cuerpo de error exacto: solo `error` y `requestId`, con las cabeceras de errores.
pub fn assert_error(resp: &Resp, status: StatusCode, code: &str) {
    assert_eq!(resp.status, status, "{}", resp.text());
    let body = resp.json();
    let obj = body.as_object().unwrap();
    assert_eq!(obj.len(), 2, "campos de mas en el error: {body}");
    assert_eq!(obj["error"], code, "{body}");
    let id = obj["requestId"].as_str().unwrap();
    assert!(!id.is_empty());
    assert_eq!(resp.header("x-request-id"), Some(id));
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert_eq!(resp.header("content-type"), Some("application/json"));
    assert_eq!(resp.header("x-content-type-options"), Some("nosniff"));
}
