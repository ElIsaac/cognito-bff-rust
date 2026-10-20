use std::sync::Arc;
use std::time::Duration;

use application::{App, AppConfig, CallbackParams, RefreshRetry, StartLoginOutcome};
use domain::{
    Email, IdHash, PendingPolicy, Session, SessionId, SessionPolicy, SessionPolicyConfig, Subject, UserInfo,
    WsTicketPolicy,
};
use in_memory::MemPorts;

pub const ORIGIN: &str = "https://app.example.com";
pub const CSRF_HEADER: &str = "x-requested-with";
pub const MAX_BODY: usize = 1024 * 1024;
pub const TENANT: &str = "tenant-42";

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

pub fn user() -> UserInfo {
    UserInfo::new(
        Subject::new("user-1".to_owned()).unwrap(),
        Some(Email::new("ana@example.com".to_owned()).unwrap()),
        Some("Ana".to_owned()),
        vec![],
    )
    .with_attributes([("custom:tenant_id".to_owned(), TENANT.to_owned())])
}

pub struct Env {
    pub ports: Arc<MemPorts>,
    pub app: App<MemPorts>,
}

impl Env {
    /// Debe llamarse dentro de un runtime de tokio (el reloj toma el instante actual).
    pub fn new() -> Self {
        Self::with(|_| {})
    }

    pub fn with(tweak: impl FnOnce(&mut AppConfig)) -> Self {
        let mut cfg = config();
        tweak(&mut cfg);
        let ports = Arc::new(MemPorts::new());
        let app = App::new(Arc::clone(&ports), cfg);
        Self { ports, app }
    }

    pub async fn advance(&self, d: Duration) {
        self.ports.clock().advance(d).await;
    }

    pub fn advance_secs(&self, s: u64) -> impl Future<Output = ()> + '_ {
        self.advance(Duration::from_secs(s))
    }
}

/// Login en curso tal como lo ve el navegador.
pub struct Started {
    pub cookie: String,
    pub state: String,
    pub url: String,
}

pub fn query_param(url: &str, key: &str) -> String {
    let query = url.split_once('?').unwrap().1;
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
        .unwrap()
        .to_owned()
}

pub async fn start(env: &Env, return_to: Option<&str>) -> Started {
    let outcome = env.app.start_login(None, return_to).await.unwrap();
    let StartLoginOutcome::Redirect {
        authorization_url,
        pending_id,
        ..
    } = outcome
    else {
        panic!("se esperaba redireccion a Cognito");
    };
    Started {
        cookie: pending_id.expose_secret(),
        state: query_param(&authorization_url, "state"),
        url: authorization_url,
    }
}

pub fn callback(code: &str, state: &str) -> CallbackParams {
    CallbackParams {
        code: Some(code.to_owned()),
        state: Some(state.to_owned()),
        error: None,
    }
}

/// Login completo y feliz; devuelve la cookie de sesion.
pub async fn login(env: &Env) -> String {
    let p = start(env, Some("/dashboard")).await;
    let code = env.ports.idp().issue_code(&p.state, user());
    let done = env
        .app
        .complete_login(Some(&p.cookie), callback(&code, &p.state), None)
        .await
        .unwrap();
    done.session_id.expose_secret()
}

pub fn hash_of(cookie: &str) -> IdHash {
    SessionId::parse(cookie).unwrap().hash()
}

pub fn stored(env: &Env, cookie: &str) -> Session {
    env.ports.sessions().snapshot(&hash_of(cookie)).unwrap()
}

pub fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}
