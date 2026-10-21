//! Modo `aws_iam` contra un servidor `axum` local que registra lo que recibe.

#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use application::ports::{Method, UpstreamApi, UpstreamRequest};
use aws_credential_types::Credentials;
use aws_credential_types::provider::SharedCredentialsProvider;
use axum::Router;
use axum::extract::{Request, State};
use domain::{AccessToken, ProxyPath};
use upstream_reqwest::{AwsIamSigner, ConfigError, ReqwestUpstream, UpstreamConfig};

const TOKEN_HEADER: &str = "x-bff-access-token";

type Log = Arc<Mutex<Vec<Vec<(String, String)>>>>;

async fn handler(State(log): State<Log>, req: Request) -> &'static str {
    let headers = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
        .collect();
    log.lock().unwrap().push(headers);
    "ok"
}

async fn start() -> (String, Log) {
    let log = Log::default();
    let app = Router::new().fallback(handler).with_state(Arc::clone(&log));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, log)
}

fn signer() -> AwsIamSigner {
    let creds = Credentials::new("AKID", "SECRET", Some("SESSION".to_owned()), None, "test");
    AwsIamSigner::new(TOKEN_HEADER, "us-east-2", SharedCredentialsProvider::new(creds))
        .unwrap()
        .with_clock(|| SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000))
}

fn hostile_request(method: Method, body: &[u8]) -> UpstreamRequest {
    let h = |k: &str, v: &str| (k.to_owned(), v.to_owned());
    UpstreamRequest {
        method,
        path: ProxyPath::parse("items/1").unwrap(),
        query: Some("a=1&b=2".to_owned()),
        headers: vec![
            h("authorization", "Bearer robado"),
            h("x-amz-security-token", "falso"),
            h("x-amz-date", "19700101T000000Z"),
            h("x-amz-content-sha256", "00"),
            h("x-amz-anything", "x"),
            h(TOKEN_HEADER, "del-cliente"),
            h("content-type", "application/json"),
        ],
        body: body.to_vec(),
        bearer: AccessToken::new("tok.en".to_owned()).unwrap(),
        timeout: None,
    }
}

fn value<'a>(seen: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    seen.iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .collect()
}

#[tokio::test]
async fn firma_y_manda_el_token_en_la_cabecera_configurada() {
    let (base, log) = start().await;
    let client = ReqwestUpstream::new(UpstreamConfig::new(&base).with_aws_iam(signer())).unwrap();
    let resp = client
        .forward(hostile_request(Method::Post, b"{\"a\":1}"))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);

    let seen = log.lock().unwrap()[0].clone();
    let auth = value(&seen, "authorization");
    assert_eq!(auth.len(), 1);
    assert!(
        auth[0].starts_with("AWS4-HMAC-SHA256 Credential=AKID/20231114/us-east-2/lambda/aws4_request"),
        "{}",
        auth[0]
    );
    assert!(auth[0].contains(
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-bff-access-token"
    ));
    assert_eq!(value(&seen, TOKEN_HEADER), ["tok.en"]);
    assert_eq!(value(&seen, "x-amz-security-token"), ["SESSION"]);
    assert_eq!(value(&seen, "x-amz-date"), ["20231114T221320Z"]);
    assert_eq!(value(&seen, "x-amz-content-sha256").len(), 1);
    assert_ne!(value(&seen, "x-amz-content-sha256"), ["00"]);
    assert!(value(&seen, "x-amz-anything").is_empty());
    assert_eq!(value(&seen, "content-type"), ["application/json"]);
}

#[tokio::test]
async fn sin_cuerpo_manda_el_hash_vacio() {
    let (base, log) = start().await;
    let client = ReqwestUpstream::new(UpstreamConfig::new(&base).with_aws_iam(signer())).unwrap();
    client.forward(hostile_request(Method::Get, b"")).await.unwrap();
    let seen = log.lock().unwrap()[0].clone();
    assert_eq!(
        value(&seen, "x-amz-content-sha256"),
        ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    );
}

#[tokio::test]
async fn el_modo_none_sigue_mandando_bearer() {
    let (base, log) = start().await;
    let client = ReqwestUpstream::new(UpstreamConfig::new(&base)).unwrap();
    client.forward(hostile_request(Method::Get, b"")).await.unwrap();
    let seen = log.lock().unwrap()[0].clone();
    assert_eq!(value(&seen, "authorization"), ["Bearer tok.en"]);
    // Sin `aws_iam` no se toca nada mas: lo que `application` dejo pasar sigue pasando.
    assert_eq!(value(&seen, TOKEN_HEADER), ["del-cliente"]);
}

#[test]
fn rechaza_cabeceras_de_token_reservadas() {
    let provider = || SharedCredentialsProvider::new(Credentials::new("a", "b", None, None, "t"));
    for bad in ["authorization", "host", "cookie", "x-amz-date", "X-Upper", ""] {
        assert_eq!(
            AwsIamSigner::new(bad, "us-east-2", provider()).unwrap_err(),
            ConfigError::TokenHeader,
            "{bad}"
        );
    }
    assert_eq!(
        AwsIamSigner::new(TOKEN_HEADER, "", provider()).unwrap_err(),
        ConfigError::Region
    );
}
