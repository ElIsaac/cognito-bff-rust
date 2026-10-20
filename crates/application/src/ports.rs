//! Puertos: lo unico que la capa de aplicacion sabe del mundo exterior.
//!
//! Todos los metodos asincronos devuelven `impl Future + Send` (RPITIT): axum exige futuros
//! `Send` y `async fn` en traits no lo garantiza. Ningun tipo de una libreria externa
//! aparece en estas firmas.

use std::future::Future;
use std::time::Duration;

use domain::{
    AccessToken, AuthCode, CodeChallenge, DeviceName, IdHash, Nonce, Password, PendingAuth, ProxyPath,
    RefreshToken, Session, State, Timestamp, TokenSet, TotpCode, TotpSecret, UserInfo, Version, WsTicket,
};

/// Error de un adaptador. No lleva detalles internos hacia arriba: el adaptador los
/// registra en su propio log antes de devolverlo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdapterError {
    /// Fallo transitorio (red, throttling, 5xx): se puede reintentar.
    #[error("fallo transitorio")]
    Transient,
    /// Fallo permanente o inesperado.
    #[error("fallo permanente")]
    Permanent,
}

// ---------------------------------------------------------------------------------------
// Proveedor de identidad
// ---------------------------------------------------------------------------------------

/// Parametros de la URL de autorizacion.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub state: State,
    pub nonce: Nonce,
    pub code_challenge: CodeChallenge,
}

/// Resultado de canjear el `code`: tokens y claims del ID token ya validados (firma,
/// `iss`, `aud`, `exp`, `iat`, `nonce`, `alg`).
#[derive(Debug, Clone)]
pub struct TokenGrant {
    pub tokens: TokenSet,
    pub access_expires_in: Duration,
    pub user: UserInfo,
}

/// Resultado de un refresh. `refresh` es `Some` si Cognito roto el refresh token.
#[derive(Debug, Clone)]
pub struct RefreshGrant {
    pub access: AccessToken,
    pub refresh: Option<RefreshToken>,
    pub access_expires_in: Duration,
    /// Claims del ID token nuevo, si vino uno valido.
    pub user: Option<UserInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdpError {
    /// `invalid_grant`: code canjeado o caducado, refresh revocado o caducado.
    #[error("grant invalido")]
    InvalidGrant,
    /// El ID token no paso la validacion.
    #[error("id token rechazado")]
    TokenRejected,
    #[error(transparent)]
    Adapter(#[from] AdapterError),
}

pub trait IdentityProvider: Send + Sync {
    fn authorization_url(&self, req: &AuthorizationRequest) -> String;

    fn exchange_code(
        &self,
        code: &AuthCode,
        verifier: &domain::CodeVerifier,
        nonce: &Nonce,
    ) -> impl Future<Output = Result<TokenGrant, IdpError>> + Send;

    fn refresh(&self, refresh: &RefreshToken) -> impl Future<Output = Result<RefreshGrant, IdpError>> + Send;

    fn revoke(&self, refresh: &RefreshToken) -> impl Future<Output = Result<(), IdpError>> + Send;

    /// URL de `/logout` del Hosted UI con `client_id` y `logout_uri`.
    fn logout_url(&self) -> String;
}

// ---------------------------------------------------------------------------------------
// Cuenta del usuario (decision 48)
// ---------------------------------------------------------------------------------------

/// Rechazo de una operacion de cuenta, ya en la lista blanca que ve el usuario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AccountError {
    #[error("code_mismatch")]
    CodeMismatch,
    #[error("code_expired")]
    CodeExpired,
    /// Contrasena actual incorrecta o access token que Cognito ya no acepta.
    #[error("not_authorized")]
    NotAuthorized,
    /// La contrasena nueva no cumple la politica del pool.
    #[error("invalid_password")]
    InvalidPassword,
    /// Verificacion o preferencia sin un TOTP asociado valido.
    #[error("mfa_setup_invalid")]
    MfaSetupInvalid,
    #[error("too_many_requests")]
    TooManyRequests,
    #[error(transparent)]
    Adapter(#[from] AdapterError),
}

/// Autoservicio de la cuenta con el access token de la sesion (`aws.cognito.signin.user.admin`).
pub trait AccountManager: Send + Sync {
    /// `true` si el TOTP esta activo para el usuario.
    fn mfa_status(&self, access: &AccessToken) -> impl Future<Output = Result<bool, AccountError>> + Send;

    fn associate_totp(
        &self,
        access: &AccessToken,
    ) -> impl Future<Output = Result<TotpSecret, AccountError>> + Send;

    fn verify_totp(
        &self,
        access: &AccessToken,
        code: &TotpCode,
        device: Option<&DeviceName>,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;

    /// Activa (como preferido) o desactiva el TOTP.
    fn set_totp(
        &self,
        access: &AccessToken,
        enabled: bool,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;

    fn change_password(
        &self,
        access: &AccessToken,
        previous: &Password,
        proposed: &Password,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;
}

// ---------------------------------------------------------------------------------------
// Almacenes
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    Updated,
    /// La version guardada no era la esperada (o la sesion ya no existe).
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseOutcome {
    /// Lease tomado; la sesion queda en `version`.
    Acquired { version: Version },
    /// Otra invocacion cambio la sesion o tiene un lease vigente.
    Conflict,
}

pub trait SessionRepository: Send + Sync {
    fn get(&self, id: &IdHash) -> impl Future<Output = Result<Option<Session>, AdapterError>> + Send;

    /// Crea la sesion; `ttl` es el atributo de borrado diferido del almacen.
    fn create(&self, s: &Session, ttl: Timestamp) -> impl Future<Output = Result<(), AdapterError>> + Send;

    /// Reemplaza la sesion si la version guardada es `expected`. `s.version` es la nueva
    /// version (normalmente `expected.next()`).
    fn update_if_version(
        &self,
        s: &Session,
        expected: Version,
        ttl: Timestamp,
    ) -> impl Future<Output = Result<UpdateOutcome, AdapterError>> + Send;

    /// Condicion atomica: `version = expected AND (sin lease OR lease < now)`. Si se cumple
    /// escribe `refresh_lock_until = until` y `version = expected + 1`.
    fn acquire_refresh_lease(
        &self,
        id: &IdHash,
        expected: Version,
        now: Timestamp,
        until: Timestamp,
    ) -> impl Future<Output = Result<LeaseOutcome, AdapterError>> + Send;

    fn delete(&self, id: &IdHash) -> impl Future<Output = Result<(), AdapterError>> + Send;
}

pub trait PendingAuthStore: Send + Sync {
    fn put(&self, p: &PendingAuth, ttl: Timestamp) -> impl Future<Output = Result<(), AdapterError>> + Send;

    /// Lectura y borrado atomicos: una segunda llamada con el mismo id devuelve `None`.
    fn consume(&self, id: &IdHash) -> impl Future<Output = Result<Option<PendingAuth>, AdapterError>> + Send;
}

pub trait WsTicketStore: Send + Sync {
    fn put(&self, t: &WsTicket, ttl: Timestamp) -> impl Future<Output = Result<(), AdapterError>> + Send;

    /// Lectura y borrado atomicos (lo usa el servicio de WebSocket; aqui sirve para tests).
    fn consume(&self, id: &IdHash) -> impl Future<Output = Result<Option<WsTicket>, AdapterError>> + Send;
}

// ---------------------------------------------------------------------------------------
// Secretos
// ---------------------------------------------------------------------------------------

/// Valor de un secreto. `Debug` redactado, sin `Display`.
#[derive(Clone)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(v: String) -> Self {
        Self(v)
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

/// Valores vigentes de un secreto: el actual y, durante una rotacion, el anterior
/// (`AWSPREVIOUS`).
#[derive(Debug, Clone)]
pub struct SecretVersions {
    pub current: SecretValue,
    pub previous: Option<SecretValue>,
}

pub trait SecretProvider: Send + Sync {
    /// Con cache TTL. `name` es el identificador logico configurado (ARN o nombre).
    fn get(&self, name: &str) -> impl Future<Output = Result<SecretVersions, AdapterError>> + Send;

    /// Fuerza la recarga en la siguiente `get` (p. ej. tras `invalid_client`).
    fn invalidate(&self, name: &str);
}

// ---------------------------------------------------------------------------------------
// Upstream
// ---------------------------------------------------------------------------------------

/// Metodos HTTP que el proxy acepta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

impl Method {
    /// `true` para los metodos que pueden cambiar estado (exigen CSRF).
    pub fn is_unsafe(self) -> bool {
        matches!(self, Self::Post | Self::Put | Self::Patch | Self::Delete)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
        }
    }
}

/// Cabecera ya normalizada (nombre en minusculas).
pub type Header = (String, String);

#[derive(Debug, Clone)]
pub struct UpstreamRequest {
    pub method: Method,
    pub path: ProxyPath,
    /// Query cruda tal como llego (sin `?`), o `None`.
    pub query: Option<String>,
    /// Ya filtradas por lista blanca (`headers::request_allowlist`).
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
    pub bearer: AccessToken,
    /// Tope de esta llamada (lo que queda del presupuesto de la peticion). El adaptador
    /// aplica el menor entre este y el suyo.
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamError {
    #[error("timeout")]
    Timeout,
    #[error("respuesta demasiado grande")]
    TooLarge,
    #[error("upstream no disponible")]
    Unavailable,
}

pub trait UpstreamApi: Send + Sync {
    fn forward(
        &self,
        req: UpstreamRequest,
    ) -> impl Future<Output = Result<UpstreamResponse, UpstreamError>> + Send;
}

// ---------------------------------------------------------------------------------------
// Reloj y aleatoriedad
// ---------------------------------------------------------------------------------------

pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;

    /// Lectura monotona con precision de milisegundos, desde un origen arbitrario. Solo
    /// sirve para medir intervalos (presupuesto de la peticion).
    fn monotonic(&self) -> Duration;

    /// Espera (backoff). En tests avanza un reloj simulado.
    fn sleep(&self, d: Duration) -> impl Future<Output = ()> + Send;
}

pub trait RandomGenerator: Send + Sync {
    /// 32 bytes de un CSPRNG.
    fn bytes32(&self) -> [u8; 32];

    /// Entero uniforme en `[0, upper)`; `upper` > 0. Solo para jitter, no para secretos.
    fn below(&self, upper: u64) -> u64;
}

// ---------------------------------------------------------------------------------------
// Agrupador
// ---------------------------------------------------------------------------------------

/// Todos los puertos de una instancia. Cada caso de uso es generico sobre `P: Ports`.
pub trait Ports: Send + Sync + 'static {
    type Idp: IdentityProvider;
    type Account: AccountManager;
    type Sessions: SessionRepository;
    type Pending: PendingAuthStore;
    type Tickets: WsTicketStore;
    type Upstream: UpstreamApi;
    type Clock: Clock;
    type Rng: RandomGenerator;

    fn idp(&self) -> &Self::Idp;
    fn account(&self) -> &Self::Account;
    fn sessions(&self) -> &Self::Sessions;
    fn pending(&self) -> &Self::Pending;
    fn tickets(&self) -> &Self::Tickets;
    fn upstream(&self) -> &Self::Upstream;
    fn clock(&self) -> &Self::Clock;
    fn rng(&self) -> &Self::Rng;
}
