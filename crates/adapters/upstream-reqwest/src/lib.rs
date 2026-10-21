//! `UpstreamApi` sobre `reqwest`.
//!
//! - Destino: `UPSTREAM_BASE_URL` (https, sin barra final) + `/` + `ProxyPath` + `?query`.
//! - Cabeceras: solo las recibidas (ya filtradas por `application`) mas
//!   `authorization: Bearer <access>`; una `authorization` recibida se descarta.
//! - Modo opcional `aws_iam` (Function URL con `AuthType: AWS_IAM`): la peticion se firma con
//!   `SigV4` (modulo `iam`) y el access token, crudo, va en la cabecera configurada; se descartan las
//!   `authorization`, `x-amz-*` y la cabecera del token que traiga el cliente.
//! - Timeout total (conexion, cabeceras y cuerpo) configurable; si la peticion trae un tope
//!   propio (lo que queda de su presupuesto) rige el menor de los dos; sin redirecciones; sin
//!   proxy de entorno; cuerpo de la respuesta leido en streaming con tope.
//! - Una respuesta HTTP (incluidas 3xx, 4xx y 5xx del upstream) se devuelve tal cual; solo
//!   los fallos de red, el timeout y el exceso de tamano son `UpstreamError`.
//! - Las cabeceras de la respuesta (incluidos varios `set-cookie`) llegan sin filtrar:
//!   las filtra `application`.

mod iam;

use std::time::Duration;

use application::ports::{Method, UpstreamApi, UpstreamError, UpstreamRequest, UpstreamResponse};
use reqwest::header::{AUTHORIZATION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use url::Url;

pub use iam::{AwsIamSigner, validate_token_header};

/// `PROXY_TIMEOUT_SECS` por defecto.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Tope de la respuesta por defecto (6 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 6 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("UPSTREAM_BASE_URL no es una URL valida")]
    InvalidUrl,
    #[error("UPSTREAM_BASE_URL debe usar https")]
    NotHttps,
    #[error("UPSTREAM_BASE_URL no debe terminar en `/`")]
    TrailingSlash,
    #[error("UPSTREAM_BASE_URL no debe llevar credenciales, query ni fragmento")]
    UnexpectedParts,
    #[error("UPSTREAM_TOKEN_HEADER no es valido")]
    TokenHeader,
    #[error("la region de la firma SigV4 no puede estar vacia")]
    Region,
    #[error("no se pudo construir el cliente HTTP")]
    Client,
}

#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub base_url: String,
    pub timeout: Duration,
    pub max_response_bytes: usize,
    /// `Some` activa el modo `aws_iam`; `None` es el bearer de siempre.
    pub aws_iam: Option<AwsIamSigner>,
}

impl UpstreamConfig {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            aws_iam: None,
        }
    }

    #[must_use]
    pub fn with_aws_iam(mut self, signer: AwsIamSigner) -> Self {
        self.aws_iam = Some(signer);
        self
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_max_response_bytes(mut self, max: usize) -> Self {
        self.max_response_bytes = max;
        self
    }
}

/// Cliente del upstream. Barato de clonar: comparte el pool de conexiones.
#[derive(Debug, Clone)]
pub struct ReqwestUpstream {
    client: reqwest::Client,
    base: String,
    timeout: Duration,
    max_response_bytes: usize,
    aws_iam: Option<AwsIamSigner>,
}

fn validate_base(base: &str) -> Result<(), ConfigError> {
    let url = Url::parse(base).map_err(|_| ConfigError::InvalidUrl)?;
    let scheme_ok = url.scheme() == "https" || (cfg!(feature = "insecure-http") && url.scheme() == "http");
    if !scheme_ok {
        return Err(ConfigError::NotHttps);
    }
    if url.host_str().is_none() {
        return Err(ConfigError::InvalidUrl);
    }
    if base.ends_with('/') {
        return Err(ConfigError::TrailingSlash);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::UnexpectedParts);
    }
    Ok(())
}

impl ReqwestUpstream {
    /// # Errors
    /// `ConfigError` si la URL base no es valida o no es `https` (con la feature de pruebas
    /// `insecure-http` tambien se acepta `http`).
    pub fn new(config: UpstreamConfig) -> Result<Self, ConfigError> {
        validate_base(&config.base_url)?;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(config.timeout)
            .build()
            .map_err(|_| ConfigError::Client)?;
        Ok(Self {
            client,
            base: config.base_url,
            timeout: config.timeout,
            max_response_bytes: config.max_response_bytes,
            aws_iam: config.aws_iam,
        })
    }

    fn url_for(&self, req: &UpstreamRequest) -> String {
        let mut url = format!("{}/{}", self.base, req.path.as_str());
        if let Some(q) = &req.query {
            url.push('?');
            url.push_str(q);
        }
        url
    }
}

fn to_method(m: Method) -> reqwest::Method {
    match m {
        Method::Get => reqwest::Method::GET,
        Method::Head => reqwest::Method::HEAD,
        Method::Post => reqwest::Method::POST,
        Method::Put => reqwest::Method::PUT,
        Method::Patch => reqwest::Method::PATCH,
        Method::Delete => reqwest::Method::DELETE,
        Method::Options => reqwest::Method::OPTIONS,
    }
}

fn request_headers(req: &UpstreamRequest, iam: Option<&AwsIamSigner>) -> Result<HeaderMap, UpstreamError> {
    let mut map = HeaderMap::new();
    for (name, value) in &req.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid_header())?;
        // `host` lo fija reqwest desde la URL; `authorization` solo la pone este adaptador.
        if name == HOST || name == AUTHORIZATION {
            continue;
        }
        // En `aws_iam` el navegador tampoco puede inyectar `x-amz-*` ni la cabecera del token.
        if iam.is_some_and(|s| name.as_str().starts_with("x-amz-") || name == *s.token_header()) {
            continue;
        }
        let value = HeaderValue::from_str(value).map_err(|_| invalid_header())?;
        map.append(name, value);
    }
    let (name, raw) = match iam {
        Some(s) => (s.token_header().clone(), req.bearer.expose_secret().to_owned()),
        None => (AUTHORIZATION, format!("Bearer {}", req.bearer.expose_secret())),
    };
    let mut token = HeaderValue::from_str(&raw).map_err(|_| invalid_header())?;
    token.set_sensitive(true);
    map.insert(name, token);
    Ok(map)
}

fn invalid_header() -> UpstreamError {
    tracing::error!("cabecera de peticion no valida para el upstream");
    UpstreamError::Unavailable
}

fn map_error(e: &reqwest::Error) -> UpstreamError {
    if e.is_timeout() {
        UpstreamError::Timeout
    } else {
        // Sin `e` completo: puede incluir la URL con la query.
        tracing::warn!(
            connect = e.is_connect(),
            body = e.is_body(),
            decode = e.is_decode(),
            "fallo al llamar al upstream"
        );
        UpstreamError::Unavailable
    }
}

impl UpstreamApi for ReqwestUpstream {
    async fn forward(&self, req: UpstreamRequest) -> Result<UpstreamResponse, UpstreamError> {
        let mut url = self.url_for(&req);
        let mut headers = request_headers(&req, self.aws_iam.as_ref())?;
        if let Some(signer) = &self.aws_iam {
            // Se firma exactamente la URL que se envia (ya normalizada por `url`).
            url = Url::parse(&url).map_err(|_| invalid_header())?.into();
            let signed = signer
                .sign(to_method(req.method).as_str(), &url, &headers, &req.body)
                .await
                .map_err(|()| UpstreamError::Unavailable)?;
            for (name, value) in signed {
                headers.insert(name, value);
            }
        }
        let timeout = req.timeout.map_or(self.timeout, |t| t.min(self.timeout));
        let mut builder = self
            .client
            .request(to_method(req.method), url)
            .headers(headers)
            .timeout(timeout);
        if !req.body.is_empty() {
            builder = builder.body(req.body);
        } else if matches!(req.method, Method::Post | Method::Put | Method::Patch) {
            // Un POST/PUT/PATCH sin cuerpo declara `content-length: 0` (reqwest no lo hace).
            builder = builder.header(CONTENT_LENGTH, "0");
        }

        let mut resp = builder.send().await.map_err(|e| map_error(&e))?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();

        if resp
            .content_length()
            .is_some_and(|len| usize::try_from(len).is_ok_and(|l| l > self.max_response_bytes))
        {
            return Err(UpstreamError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| map_error(&e))? {
            if body.len().saturating_add(chunk.len()) > self.max_response_bytes {
                return Err(UpstreamError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(UpstreamResponse {
            status,
            headers,
            body,
        })
    }
}
