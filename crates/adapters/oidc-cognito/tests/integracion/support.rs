//! Cognito simulado, llaves de prueba y fakes compartidos por los tests.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use application::ports::{
    AdapterError, IdentityProvider, IdpError, SecretProvider, SecretValue, SecretVersions, TokenGrant,
};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_SHA256};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use domain::{AuthCode, CodeVerifier, Nonce};
use oidc_cognito::{CognitoConfig, CognitoIdp};
use serde_json::{Value, json};
use url::Url;

pub const POOL: &str = "us-test-1_PoolX";
pub const CLIENT_ID: &str = "client-id-de-prueba";
pub const CLIENT_SECRET: &str = "client-secret-super-secreto-0001";
pub const REDIRECT_URI: &str = "https://app.example.com/auth/callback";
pub const LOGOUT_URI: &str = "https://app.example.com/";
pub const ACCESS_TOKEN: &str = "access-token-opaco-abcdefghijklmnop";
pub const REFRESH_TOKEN: &str = "refresh-token-opaco-abcdefghijklmnop";
pub const NEW_REFRESH_TOKEN: &str = "refresh-token-rotado-abcdefghijklmnop";
pub const CODE: &str = "codigo-de-autorizacion-0123456789abcdef";

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn b64(data: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn nonce() -> Nonce {
    Nonce::from_bytes([7u8; 32])
}

pub fn other_nonce() -> Nonce {
    Nonce::from_bytes([8u8; 32])
}

pub fn verifier() -> CodeVerifier {
    CodeVerifier::from_bytes([9u8; 32])
}

pub fn code() -> AuthCode {
    AuthCode::new(CODE.into()).unwrap()
}

// ---------------------------------------------------------------------------------------
// Llaves RSA
// ---------------------------------------------------------------------------------------

/// Par RSA 2048 con su `kid`. La privada vive solo en memoria durante el test.
pub struct TestKey {
    pub kid: String,
    pair: RsaKeyPair,
    pub n: String,
    pub e: String,
    pub public_der: Vec<u8>,
}

fn der_read(input: &[u8], tag: u8) -> (&[u8], &[u8]) {
    assert_eq!(input[0], tag, "tag DER inesperado");
    let (len, off) = if input[1] < 0x80 {
        (usize::from(input[1]), 2)
    } else {
        let n = usize::from(input[1] & 0x7f);
        let len = input[2..2 + n]
            .iter()
            .fold(0usize, |a, b| (a << 8) | usize::from(*b));
        (len, 2 + n)
    };
    (&input[off..off + len], &input[off + len..])
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` (PKCS#1).
fn rsa_components(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    const SEQUENCE: u8 = 0x30;
    const INTEGER: u8 = 0x02;
    let (seq, _) = der_read(der, SEQUENCE);
    let (n, rest) = der_read(seq, INTEGER);
    let (e, _) = der_read(rest, INTEGER);
    let strip = |v: &[u8]| {
        let start = v.iter().position(|b| *b != 0).unwrap_or(v.len());
        v[start..].to_vec()
    };
    (strip(n), strip(e))
}

impl TestKey {
    fn generate(kid: &str) -> Self {
        let pair = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let public_der = pair.public_key().as_ref().to_vec();
        let (n, e) = rsa_components(&public_der);
        Self {
            kid: kid.into(),
            pair,
            n: b64(n),
            e: b64(e),
            public_der,
        }
    }

    /// Misma llave publica con otro `kid` (para anunciar kids nuevos sin generar otra).
    pub fn jwk(&self) -> Value {
        self.jwk_as(&self.kid)
    }

    pub fn jwk_as(&self, kid: &str) -> Value {
        json!({"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": self.n, "e": self.e})
    }

    pub fn header(&self) -> Value {
        json!({"alg": "RS256", "typ": "JWT", "kid": self.kid})
    }

    /// Firma `header.claims` con RS256.
    pub fn sign(&self, header: &Value, claims: &Value) -> String {
        let input = format!("{}.{}", b64(header.to_string()), b64(claims.to_string()));
        let mut sig = vec![0u8; self.pair.public_modulus_len()];
        self.pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input.as_bytes(),
                &mut sig,
            )
            .unwrap();
        format!("{input}.{}", b64(sig))
    }

    /// Token RS256 con el `kid` de esta llave.
    pub fn token(&self, claims: &Value) -> String {
        self.sign(&self.header(), claims)
    }
}

pub const KID_A: &str = "kid-legitimo-a";
pub const KID_B: &str = "kid-legitimo-b";

struct Keys {
    a: TestKey,
    b: TestKey,
    /// Del atacante: nunca se publica.
    attacker: TestKey,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| Keys {
        a: TestKey::generate(KID_A),
        b: TestKey::generate(KID_B),
        attacker: TestKey::generate(KID_A),
    })
}

/// Llave publicada desde el inicio.
pub fn key_a() -> &'static TestKey {
    &keys().a
}

/// Llave que Cognito publica tras una rotacion.
pub fn key_b() -> &'static TestKey {
    &keys().b
}

/// Llave ajena que reutiliza el `kid` de la A.
pub fn key_attacker() -> &'static TestKey {
    &keys().attacker
}

// ---------------------------------------------------------------------------------------
// Cognito simulado
// ---------------------------------------------------------------------------------------

/// Respuesta programada de un endpoint.
#[derive(Clone)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub delay: Duration,
}

impl Reply {
    pub fn json(status: u16, body: &Value) -> Self {
        Self {
            status,
            body: body.to_string(),
            delay: Duration::ZERO,
        }
    }

    pub fn raw(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.into(),
            delay: Duration::ZERO,
        }
    }

    pub fn error(status: u16, error: &str) -> Self {
        Self::json(status, &json!({"error": error}))
    }

    #[must_use]
    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Respuesta 200 estandar del token endpoint.
    pub fn tokens(id_token: Option<&str>, refresh: Option<&str>) -> Self {
        let mut body = json!({"access_token": ACCESS_TOKEN, "expires_in": 3600, "token_type": "Bearer"});
        if let Some(t) = id_token {
            body["id_token"] = json!(t);
        }
        if let Some(r) = refresh {
            body["refresh_token"] = json!(r);
        }
        Self::json(200, &body)
    }
}

/// Peticion recibida por el servidor simulado.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub path: String,
    pub authorization: Option<String>,
    pub content_type: Option<String>,
    pub form: Vec<(String, String)>,
}

impl Recorded {
    pub fn field(&self, name: &str) -> Option<&str> {
        self.form.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

struct Inner {
    jwks: Mutex<Vec<Value>>,
    jwks_status: Mutex<u16>,
    jwks_hits: AtomicUsize,
    token_replies: Mutex<VecDeque<Reply>>,
    revoke_replies: Mutex<VecDeque<Reply>>,
    expected_secret: Mutex<Option<String>>,
    requests: Mutex<Vec<Recorded>>,
}

pub struct Mock {
    inner: Arc<Inner>,
    pub base: Url,
}

async fn reply_to_response(r: Reply) -> Response {
    if !r.delay.is_zero() {
        tokio::time::sleep(r.delay).await;
    }
    (
        StatusCode::from_u16(r.status).unwrap(),
        [(header::CONTENT_TYPE, "application/json")],
        r.body,
    )
        .into_response()
}

async fn jwks_handler(State(m): State<Arc<Inner>>) -> Response {
    m.jwks_hits.fetch_add(1, Ordering::SeqCst);
    let status = *m.jwks_status.lock().unwrap();
    let keys = m.jwks.lock().unwrap().clone();
    reply_to_response(Reply::json(status, &json!({"keys": keys}))).await
}

async fn oauth_handler(m: Arc<Inner>, path: &str, headers: HeaderMap, body: Bytes) -> Response {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let form = url::form_urlencoded::parse(&body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    m.requests.lock().unwrap().push(Recorded {
        path: path.into(),
        authorization: authorization.clone(),
        content_type,
        form,
    });
    let expected = m.expected_secret.lock().unwrap().clone();
    if let Some(secret) = expected {
        let ok = format!("Basic {}", STANDARD.encode(format!("{CLIENT_ID}:{secret}")));
        if authorization.as_deref() != Some(ok.as_str()) {
            return reply_to_response(Reply::error(401, "invalid_client")).await;
        }
    }
    let queue = if path == "/oauth2/token" {
        &m.token_replies
    } else {
        &m.revoke_replies
    };
    let reply = queue
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or_else(|| Reply::error(500, "sin_respuesta_programada"));
    reply_to_response(reply).await
}

impl Mock {
    async fn start() -> Self {
        let inner = Arc::new(Inner {
            jwks: Mutex::new(vec![key_a().jwk()]),
            jwks_status: Mutex::new(200),
            jwks_hits: AtomicUsize::new(0),
            token_replies: Mutex::default(),
            revoke_replies: Mutex::default(),
            expected_secret: Mutex::new(Some(CLIENT_SECRET.into())),
            requests: Mutex::default(),
        });
        let app = Router::new()
            .route(&format!("/{POOL}/.well-known/jwks.json"), get(jwks_handler))
            .route(
                "/oauth2/token",
                post(|State(m): State<Arc<Inner>>, h: HeaderMap, b: Bytes| async move {
                    oauth_handler(m, "/oauth2/token", h, b).await
                }),
            )
            .route(
                "/oauth2/revoke",
                post(|State(m): State<Arc<Inner>>, h: HeaderMap, b: Bytes| async move {
                    oauth_handler(m, "/oauth2/revoke", h, b).await
                }),
            )
            .with_state(inner.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            inner,
            base: Url::parse(&format!("http://{addr}")).unwrap(),
        }
    }

    pub fn issuer(&self) -> String {
        format!("{}{POOL}", self.base.as_str())
    }

    /// Descargas del JWKS desde que arranco el servidor (incluye la de `warm_up`).
    pub fn jwks_hits(&self) -> usize {
        self.inner.jwks_hits.load(Ordering::SeqCst)
    }

    pub fn publish_keys(&self, keys: Vec<Value>) {
        *self.inner.jwks.lock().unwrap() = keys;
    }

    pub fn set_jwks_status(&self, status: u16) {
        *self.inner.jwks_status.lock().unwrap() = status;
    }

    /// `None` desactiva la verificacion de Basic auth.
    pub fn set_expected_secret(&self, secret: Option<&str>) {
        *self.inner.expected_secret.lock().unwrap() = secret.map(str::to_owned);
    }

    pub fn push_token(&self, r: Reply) {
        self.inner.token_replies.lock().unwrap().push_back(r);
    }

    pub fn push_revoke(&self, r: Reply) {
        self.inner.revoke_replies.lock().unwrap().push_back(r);
    }

    pub fn requests(&self, path: &str) -> Vec<Recorded> {
        self.inner
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == path)
            .cloned()
            .collect()
    }

    pub fn token_requests(&self) -> Vec<Recorded> {
        self.requests("/oauth2/token")
    }

    pub fn basic(secret: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{CLIENT_ID}:{secret}")))
    }
}

// ---------------------------------------------------------------------------------------
// SecretProvider fake
// ---------------------------------------------------------------------------------------

struct SecretsInner {
    current: Mutex<String>,
    after_invalidate: Mutex<Option<String>>,
    failure: Mutex<Option<AdapterError>>,
    gets: AtomicUsize,
    invalidations: AtomicUsize,
}

/// Cuenta llamadas a `get`/`invalidate`. `rotate_on_invalidate` simula la recarga que hace
/// el proveedor real tras `invalidate`.
#[derive(Clone)]
pub struct FakeSecrets(Arc<SecretsInner>);

impl std::fmt::Debug for FakeSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeSecrets([REDACTED])")
    }
}

impl FakeSecrets {
    pub fn new(secret: &str) -> Self {
        Self(Arc::new(SecretsInner {
            current: Mutex::new(secret.into()),
            after_invalidate: Mutex::new(None),
            failure: Mutex::new(None),
            gets: AtomicUsize::new(0),
            invalidations: AtomicUsize::new(0),
        }))
    }

    pub fn set_current(&self, secret: &str) {
        *self.0.current.lock().unwrap() = secret.into();
    }

    pub fn rotate_on_invalidate(&self, secret: &str) {
        *self.0.after_invalidate.lock().unwrap() = Some(secret.into());
    }

    pub fn fail_with(&self, e: AdapterError) {
        *self.0.failure.lock().unwrap() = Some(e);
    }

    pub fn gets(&self) -> usize {
        self.0.gets.load(Ordering::SeqCst)
    }

    pub fn invalidations(&self) -> usize {
        self.0.invalidations.load(Ordering::SeqCst)
    }
}

impl SecretProvider for FakeSecrets {
    fn get(&self, _name: &str) -> impl Future<Output = Result<SecretVersions, AdapterError>> + Send {
        self.0.gets.fetch_add(1, Ordering::SeqCst);
        let failure = *self.0.failure.lock().unwrap();
        let current = self.0.current.lock().unwrap().clone();
        std::future::ready(match failure {
            Some(e) => Err(e),
            None => Ok(SecretVersions {
                current: SecretValue::new(current),
                previous: None,
            }),
        })
    }

    fn invalidate(&self, _name: &str) {
        self.0.invalidations.fetch_add(1, Ordering::SeqCst);
        if let Some(next) = self.0.after_invalidate.lock().unwrap().take() {
            *self.0.current.lock().unwrap() = next;
        }
    }
}

// ---------------------------------------------------------------------------------------
// Entorno
// ---------------------------------------------------------------------------------------

pub struct Env {
    pub mock: Mock,
    pub secrets: FakeSecrets,
    pub idp: CognitoIdp<FakeSecrets>,
    pub cfg: CognitoConfig,
}

pub fn base_config(mock: &Mock) -> CognitoConfig {
    CognitoConfig {
        issuer: mock.issuer(),
        domain: mock.base.clone(),
        client_id: CLIENT_ID.into(),
        client_secret_name: "arn:secreto-de-prueba".into(),
        redirect_uri: REDIRECT_URI.into(),
        logout_uri: LOGOUT_URI.into(),
        scopes: "openid email profile".into(),
        exposed_claims: vec!["custom:tenant_id".into()],
        http_timeout: Duration::from_secs(3),
        jwks_cache_ttl: Duration::from_secs(3600),
        jwks_min_refetch: Duration::from_secs(60),
        leeway: Duration::from_secs(60),
        require_https: false,
    }
}

impl Env {
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(tweak: impl FnOnce(&mut CognitoConfig)) -> Self {
        let mock = Mock::start().await;
        let mut cfg = base_config(&mock);
        tweak(&mut cfg);
        let secrets = FakeSecrets::new(CLIENT_SECRET);
        let idp = CognitoIdp::new(cfg.clone(), secrets.clone()).await.unwrap();
        Self {
            mock,
            secrets,
            idp,
            cfg,
        }
    }

    /// Claims validos de un ID token recien emitido por Cognito para `nonce()`.
    pub fn claims(&self) -> Value {
        let t = now();
        json!({
            "iss": self.cfg.issuer,
            "aud": CLIENT_ID,
            "sub": "sub-0001-aaaa",
            "token_use": "id",
            "iat": t,
            "exp": t + 3600,
            "nonce": nonce().expose_secret(),
            "email": "ana@example.com",
            "email_verified": true,
            "name": "Ana Perez",
            "cognito:groups": ["admins", "ventas"],
            "custom:tenant_id": "tenant-42",
            "custom:otro": "no-expuesto",
        })
    }

    /// Programa la respuesta del token endpoint con `id_token` y canjea el code.
    pub async fn exchange(&self, id_token: &str) -> Result<TokenGrant, IdpError> {
        self.mock
            .push_token(Reply::tokens(Some(id_token), Some(REFRESH_TOKEN)));
        self.exchange_programmed().await
    }

    /// Canjea el code con lo que ya este programado en el mock.
    pub async fn exchange_programmed(&self) -> Result<TokenGrant, IdpError> {
        self.idp.exchange_code(&code(), &verifier(), &nonce()).await
    }

    /// Canjea y exige `TokenRejected`.
    pub async fn assert_rejected(&self, id_token: &str) {
        let r = self.exchange(id_token).await;
        assert!(
            matches!(r, Err(IdpError::TokenRejected)),
            "se esperaba TokenRejected: {r:?}"
        );
    }
}
