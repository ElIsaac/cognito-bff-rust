//! Firma `SigV4` (servicio `lambda`) de las peticiones al upstream cuando este es una Function
//! URL con `AuthType: AWS_IAM`.
//!
//! `Authorization` queda ocupada por la firma, asi que el access token viaja crudo (sin
//! `Bearer `) en una cabecera configurable. Las credenciales se piden al proveedor en cada
//! peticion: el proveedor es quien las cachea y las renueva, aqui nunca se guardan.

use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_sigv4::http_request::{PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::ConfigError;

/// Nombre del servicio en el alcance de la firma de una Function URL.
const SIGNING_SERVICE: &str = "lambda";
const AMZ_PREFIX: &str = "x-amz-";
/// Cabeceras que el token no puede ocupar.
const RESERVED_TOKEN_HEADERS: [&str; 3] = ["authorization", "host", "cookie"];

/// Reloj inyectable: las pruebas fijan la hora para que la firma sea determinista.
#[derive(Clone)]
struct Clock(Arc<dyn Fn() -> SystemTime + Send + Sync>);

impl fmt::Debug for Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Clock")
    }
}

/// Valida el nombre de la cabecera del token: minusculas, token HTTP valido y ni
/// `authorization`, `host`, `cookie` ni `x-amz-*`.
///
/// # Errors
/// `ConfigError::TokenHeader` si no cumple.
pub fn validate_token_header(name: &str) -> Result<(), ConfigError> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && HeaderName::from_bytes(name.as_bytes()).is_ok()
        && !RESERVED_TOKEN_HEADERS.contains(&name)
        && !name.starts_with(AMZ_PREFIX);
    if valid {
        Ok(())
    } else {
        Err(ConfigError::TokenHeader)
    }
}

/// Firmante `SigV4`. Barato de clonar.
#[derive(Debug, Clone)]
pub struct AwsIamSigner {
    token_header: HeaderName,
    region: String,
    credentials: SharedCredentialsProvider,
    clock: Clock,
}

impl AwsIamSigner {
    /// # Errors
    /// `ConfigError::TokenHeader` si el nombre no es valido; `ConfigError::Region` si la
    /// region esta vacia.
    pub fn new(
        token_header: &str,
        region: impl Into<String>,
        credentials: SharedCredentialsProvider,
    ) -> Result<Self, ConfigError> {
        validate_token_header(token_header)?;
        let region = region.into();
        if region.is_empty() {
            return Err(ConfigError::Region);
        }
        Ok(Self {
            token_header: HeaderName::from_bytes(token_header.as_bytes())
                .map_err(|_| ConfigError::TokenHeader)?,
            region,
            credentials,
            clock: Clock(Arc::new(SystemTime::now)),
        })
    }

    /// Sustituye el reloj (pruebas).
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.clock = Clock(Arc::new(clock));
        self
    }

    pub(crate) fn token_header(&self) -> &HeaderName {
        &self.token_header
    }

    /// Firma la peticion y devuelve las cabeceras que hay que anadir: `authorization`,
    /// `x-amz-date`, `x-amz-content-sha256` y, si las credenciales son temporales,
    /// `x-amz-security-token`. `token` ya debe estar en `headers` (se firma con el resto).
    /// `Err(())` sin detalle: ni la firma ni las credenciales se registran.
    pub(crate) async fn sign(
        &self,
        method: &str,
        url: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Vec<(HeaderName, HeaderValue)>, ()> {
        let credentials = self.credentials.provide_credentials().await.map_err(|_| {
            tracing::error!("no se pudieron obtener credenciales AWS para firmar el upstream");
        })?;
        let identity: Identity = credentials.into();
        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(SIGNING_SERVICE)
            .time((self.clock.0)())
            .settings(settings)
            .build()
            .map_err(|_| tracing::error!("parametros de firma SigV4 no validos"))?
            .into();
        let signed_headers = headers
            .get(&self.token_header)
            .and_then(|v| v.to_str().ok().map(|v| (self.token_header.as_str(), v)));
        let signable =
            SignableRequest::new(method, url, signed_headers.into_iter(), SignableBody::Bytes(body))
                .map_err(|_| tracing::error!("peticion al upstream no firmable"))?;
        let (instructions, _signature) = sign(signable, &params)
            .map_err(|_| tracing::error!("fallo al firmar la peticion al upstream"))?
            .into_parts();

        let mut out = Vec::new();
        for (name, value) in instructions.headers() {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?;
            let mut value = HeaderValue::from_str(value).map_err(|_| ())?;
            if name != "x-amz-date" && name != "x-amz-content-sha256" {
                value.set_sensitive(true);
            }
            out.push((name, value));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::time::Duration;

    use aws_credential_types::Credentials;
    use sha2::{Digest, Sha256};

    use super::*;

    /// 2023-11-14T22:13:20Z.
    const FIXED_SECS: u64 = 1_700_000_000;
    const URL: &str = "https://abc.lambda-url.us-east-2.on.aws/v1/items?b=2&a=1";

    fn signer(token: Option<&str>) -> AwsIamSigner {
        let creds = Credentials::new("AKID", "SECRET", token.map(str::to_owned), None, "test");
        AwsIamSigner::new(
            "x-bff-access-token",
            "us-east-2",
            SharedCredentialsProvider::new(creds),
        )
        .unwrap()
        .with_clock(|| SystemTime::UNIX_EPOCH + Duration::from_secs(FIXED_SECS))
    }

    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-bff-access-token", HeaderValue::from_static("tok.en"));
        h
    }

    fn get<'a>(signed: &'a [(HeaderName, HeaderValue)], name: &str) -> Option<&'a str> {
        signed
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.to_str().unwrap())
    }

    #[tokio::test]
    async fn firma_sigv4_con_credenciales_estaticas() {
        let body = b"{\"a\":1}";
        let signed = signer(Some("SESSION"))
            .sign("POST", URL, &headers(), body)
            .await
            .unwrap();
        let auth = get(&signed, "authorization").unwrap();
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=AKID/20231114/us-east-2/lambda/aws4_request"),
            "{auth}"
        );
        assert!(
            auth.contains(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-bff-access-token"
            ),
            "{auth}"
        );
        assert_eq!(get(&signed, "x-amz-date"), Some("20231114T221320Z"));
        assert_eq!(get(&signed, "x-amz-security-token"), Some("SESSION"));
        let digest = Sha256::digest(body).iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        });
        assert_eq!(get(&signed, "x-amz-content-sha256"), Some(digest.as_str()));
    }

    #[tokio::test]
    async fn sin_cuerpo_firma_el_hash_de_la_cadena_vacia() {
        let signed = signer(None).sign("GET", URL, &headers(), b"").await.unwrap();
        assert_eq!(
            get(&signed, "x-amz-content-sha256"),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(get(&signed, "x-amz-security-token"), None);
        assert!(
            !get(&signed, "authorization")
                .unwrap()
                .contains("x-amz-security-token")
        );
    }

    #[tokio::test]
    async fn la_firma_es_determinista_y_depende_del_cuerpo_y_la_url() {
        async fn auth(method: &str, url: &str, body: &[u8]) -> String {
            let signed = signer(None).sign(method, url, &headers(), body).await.unwrap();
            get(&signed, "authorization").unwrap().to_owned()
        }
        let base = auth("POST", URL, b"x").await;
        assert_eq!(base, auth("POST", URL, b"x").await);
        assert_ne!(base, auth("POST", URL, b"y").await);
        assert_ne!(base, auth("GET", URL, b"x").await);
        assert_ne!(
            base,
            auth(
                "POST",
                "https://abc.lambda-url.us-east-2.on.aws/v1/items?b=2",
                b"x"
            )
            .await
        );
    }

    #[test]
    fn valida_el_nombre_de_la_cabecera_del_token() {
        for ok in ["x-bff-access-token", "x-token", "t1"] {
            assert_eq!(validate_token_header(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "authorization",
            "host",
            "cookie",
            "x-amz-date",
            "x-amz-",
            "X-Token",
            "x token",
            "x_token",
        ] {
            assert_eq!(validate_token_header(bad), Err(ConfigError::TokenHeader), "{bad}");
        }
    }
}
