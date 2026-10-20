use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use application::ports::{
    AdapterError, AuthorizationRequest, Clock, IdentityProvider, IdpError, RefreshGrant, TokenGrant,
};
use domain::{AccessToken, AuthCode, CodeVerifier, Nonce, RefreshToken, TokenSet, UserInfo};

use crate::clock::TestClock;
use crate::util::{digest, hex, lock};

const DEFAULT_ACCESS_TTL: Duration = Duration::from_hours(1);
const LOGOUT_URL: &str =
    "https://idp.test/logout?client_id=test-client&logout_uri=https%3A%2F%2Fapp.example.com%2F";

#[derive(Debug)]
struct AuthRecord {
    nonce: String,
    challenge: String,
}

#[derive(Debug)]
struct CodeRecord {
    challenge: String,
    nonce: String,
    user: UserInfo,
    used: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshStatus {
    Valid,
    Revoked,
    Replaced,
}

#[derive(Debug)]
struct RefreshRecord {
    user: UserInfo,
    status: RefreshStatus,
}

#[derive(Debug)]
struct State {
    auth_requests: HashMap<String, AuthRecord>,
    codes: HashMap<String, CodeRecord>,
    refresh_tokens: HashMap<String, RefreshRecord>,
    access_ttl: Duration,
    refresh_latency: Duration,
    rotate: bool,
    scripted_failures: VecDeque<IdpError>,
    revoked: Vec<String>,
}

/// Simula Cognito con fidelidad: PKCE S256, codes de un solo uso ligados a `state`/`nonce`,
/// refresh tokens revocables y rotables.
#[derive(Debug)]
pub struct FakeIdp {
    clock: TestClock,
    state: Mutex<State>,
    counter: AtomicU64,
    exchange_calls: AtomicUsize,
    refresh_calls: AtomicUsize,
    revoke_calls: AtomicUsize,
}

impl FakeIdp {
    pub fn new(clock: TestClock) -> Self {
        Self {
            clock,
            state: Mutex::new(State {
                auth_requests: HashMap::new(),
                codes: HashMap::new(),
                refresh_tokens: HashMap::new(),
                access_ttl: DEFAULT_ACCESS_TTL,
                refresh_latency: Duration::ZERO,
                rotate: false,
                scripted_failures: VecDeque::new(),
                revoked: Vec::new(),
            }),
            counter: AtomicU64::new(0),
            exchange_calls: AtomicUsize::new(0),
            refresh_calls: AtomicUsize::new(0),
            revoke_calls: AtomicUsize::new(0),
        }
    }

    fn unique(&self, kind: &str) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        hex(&digest(&[b"fake-idp", kind.as_bytes(), &n.to_be_bytes()]))
    }

    fn token_error() -> IdpError {
        IdpError::Adapter(AdapterError::Permanent)
    }

    /// Simula al usuario autenticandose en el Hosted UI para la peticion cuyo `state` se
    /// dio a `authorization_url`: devuelve un `code` de un solo uso ligado al challenge y
    /// al nonce de esa peticion.
    ///
    /// # Panics
    /// Si el `state` no corresponde a ninguna peticion de autorizacion registrada.
    pub fn issue_code(&self, state: &str, user: UserInfo) -> String {
        self.issue(state, user, None)
    }

    /// Igual que `issue_code`, pero el ID token llevara `nonce` en vez del de la peticion
    /// (simula un ID token reutilizado o forjado).
    ///
    /// # Panics
    /// Si el `state` no corresponde a ninguna peticion de autorizacion registrada.
    pub fn issue_code_with_nonce(&self, state: &str, user: UserInfo, nonce: &str) -> String {
        self.issue(state, user, Some(nonce))
    }

    fn issue(&self, state: &str, user: UserInfo, nonce: Option<&str>) -> String {
        let code = self.unique("code");
        let mut st = lock(&self.state);
        let Some(req) = st.auth_requests.get(state) else {
            panic!("state desconocido para el IdP de prueba");
        };
        let record = CodeRecord {
            challenge: req.challenge.clone(),
            nonce: nonce.map_or_else(|| req.nonce.clone(), str::to_owned),
            user,
            used: false,
        };
        st.codes.insert(code.clone(), record);
        code
    }

    /// Duracion del access token que se emite desde ahora (por defecto 1 h).
    pub fn set_access_ttl(&self, d: Duration) {
        lock(&self.state).access_ttl = d;
    }

    /// Latencia (reloj de prueba) de cada `refresh`.
    pub fn set_refresh_latency(&self, d: Duration) {
        lock(&self.state).refresh_latency = d;
    }

    /// Con `true`, cada refresh devuelve un refresh token nuevo e invalida el anterior.
    pub fn set_rotate_refresh(&self, on: bool) {
        lock(&self.state).rotate = on;
    }

    /// Los proximos `times` refresh devuelven `err` (tras la latencia y contados).
    pub fn fail_refresh(&self, err: IdpError, times: usize) {
        lock(&self.state)
            .scripted_failures
            .extend(std::iter::repeat_n(err, times));
    }

    pub fn exchange_calls(&self) -> usize {
        self.exchange_calls.load(Ordering::SeqCst)
    }

    pub fn refresh_calls(&self) -> usize {
        self.refresh_calls.load(Ordering::SeqCst)
    }

    pub fn revoke_calls(&self) -> usize {
        self.revoke_calls.load(Ordering::SeqCst)
    }

    /// Valores de los refresh tokens revocados, en orden.
    pub fn revoked(&self) -> Vec<String> {
        lock(&self.state).revoked.clone()
    }

    /// `true` si el refresh token existe y no esta revocado ni reemplazado.
    pub fn is_refresh_valid(&self, token: &RefreshToken) -> bool {
        lock(&self.state)
            .refresh_tokens
            .get(token.expose_secret())
            .is_some_and(|r| r.status == RefreshStatus::Valid)
    }
}

impl IdentityProvider for FakeIdp {
    fn authorization_url(&self, req: &AuthorizationRequest) -> String {
        let state = req.state.expose_secret();
        let nonce = req.nonce.expose_secret();
        let challenge = req.code_challenge.as_str().to_owned();
        let url = format!(
            "https://idp.test/oauth2/authorize?response_type=code&client_id=test-client&scope=openid\
             &state={state}&nonce={nonce}&code_challenge={challenge}&code_challenge_method=S256"
        );
        lock(&self.state)
            .auth_requests
            .insert(state, AuthRecord { nonce, challenge });
        url
    }

    async fn exchange_code(
        &self,
        code: &AuthCode,
        verifier: &CodeVerifier,
        nonce: &Nonce,
    ) -> Result<TokenGrant, IdpError> {
        self.exchange_calls.fetch_add(1, Ordering::SeqCst);
        let access = self.unique("access");
        let refresh = self.unique("refresh");
        let mut st = lock(&self.state);
        let access_ttl = st.access_ttl;
        let Some(record) = st.codes.get_mut(code.expose_secret()) else {
            return Err(IdpError::InvalidGrant);
        };
        if record.used {
            return Err(IdpError::InvalidGrant);
        }
        record.used = true;
        if verifier.challenge().as_str() != record.challenge {
            return Err(IdpError::InvalidGrant);
        }
        if !nonce.matches_claim(&record.nonce) {
            return Err(IdpError::TokenRejected);
        }
        let user = record.user.clone();
        let tokens = TokenSet {
            access: AccessToken::new(access).map_err(|_| Self::token_error())?,
            refresh: RefreshToken::new(refresh.clone()).map_err(|_| Self::token_error())?,
        };
        st.refresh_tokens.insert(
            refresh,
            RefreshRecord {
                user: user.clone(),
                status: RefreshStatus::Valid,
            },
        );
        Ok(TokenGrant {
            tokens,
            access_expires_in: access_ttl,
            user,
        })
    }

    async fn refresh(&self, refresh: &RefreshToken) -> Result<RefreshGrant, IdpError> {
        self.refresh_calls.fetch_add(1, Ordering::SeqCst);
        let latency = lock(&self.state).refresh_latency;
        if !latency.is_zero() {
            self.clock.sleep(latency).await;
        }
        let new_access = self.unique("access");
        let new_refresh = self.unique("refresh");
        let mut st = lock(&self.state);
        if let Some(err) = st.scripted_failures.pop_front() {
            return Err(err);
        }
        let access_ttl = st.access_ttl;
        let rotate = st.rotate;
        let Some(record) = st.refresh_tokens.get_mut(refresh.expose_secret()) else {
            return Err(IdpError::InvalidGrant);
        };
        if record.status != RefreshStatus::Valid {
            return Err(IdpError::InvalidGrant);
        }
        let access = AccessToken::new(new_access).map_err(|_| Self::token_error())?;
        let rotated = if rotate {
            record.status = RefreshStatus::Replaced;
            let user = record.user.clone();
            let token = RefreshToken::new(new_refresh.clone()).map_err(|_| Self::token_error())?;
            st.refresh_tokens.insert(
                new_refresh,
                RefreshRecord {
                    user,
                    status: RefreshStatus::Valid,
                },
            );
            Some(token)
        } else {
            None
        };
        Ok(RefreshGrant {
            access,
            refresh: rotated,
            access_expires_in: access_ttl,
            user: None,
        })
    }

    async fn revoke(&self, refresh: &RefreshToken) -> Result<(), IdpError> {
        self.revoke_calls.fetch_add(1, Ordering::SeqCst);
        let mut st = lock(&self.state);
        if let Some(record) = st.refresh_tokens.get_mut(refresh.expose_secret()) {
            record.status = RefreshStatus::Revoked;
        }
        st.revoked.push(refresh.expose_secret().to_owned());
        Ok(())
    }

    fn logout_url(&self) -> String {
        LOGOUT_URL.to_owned()
    }
}
