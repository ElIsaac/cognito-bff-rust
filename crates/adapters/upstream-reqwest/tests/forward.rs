//! Pruebas contra un servidor `axum` local que registra lo que recibe.

#![allow(clippy::unwrap_used)]

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use application::ports::{Method, UpstreamApi, UpstreamError, UpstreamRequest};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use domain::{AccessToken, ProxyPath};
use upstream_reqwest::{ConfigError, ReqwestUpstream, UpstreamConfig};

const MIB: usize = 1024 * 1024;

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

type Log = Arc<Mutex<Vec<Seen>>>;

async fn handler(State(log): State<Log>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let uri = parts.uri.to_string();
    log.lock().unwrap().push(Seen {
        method: parts.method.to_string(),
        uri: uri.clone(),
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
            .collect(),
        body: body.to_vec(),
    });

    let path = parts.uri.path();
    match path {
        "/lento" => {
            tokio::time::sleep(Duration::from_secs(3)).await;
            Response::new(Body::from("tarde"))
        }
        "/cuerpo-goteo" => {
            let stream = futures_util::stream::unfold(0u8, |i| async move {
                if i == 20 {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                Some((Ok::<_, Infallible>(Bytes::from_static(b"x")), i + 1))
            });
            Response::new(Body::from_stream(stream))
        }
        "/grande" => Response::new(Body::from(vec![b'a'; 2 * MIB])),
        "/exacto" => Response::new(Body::from(vec![b'a'; MIB])),
        "/grande-chunked" => {
            let chunk = Bytes::from(vec![b'a'; 64 * 1024]);
            let stream = futures_util::stream::iter((0..32).map(move |_| Ok::<_, Infallible>(chunk.clone())));
            Response::new(Body::from_stream(stream))
        }
        "/redireccion" => Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/destino")
            .body(Body::from("redirigiendo"))
            .unwrap(),
        "/cookies" => {
            let mut r = Response::new(Body::from("ok"));
            r.headers_mut()
                .append("Set-Cookie", HeaderValue::from_static("a=1; Path=/; HttpOnly"));
            r.headers_mut()
                .append("Set-Cookie", HeaderValue::from_static("b=2; Secure"));
            r.headers_mut()
                .insert("X-Mixed-Case", HeaderValue::from_static("v"));
            r
        }
        "/error" => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("fallo"))
            .unwrap(),
        _ => {
            let mut r = Response::new(Body::from(format!("eco:{uri}")));
            r.headers_mut().insert("x-eco", HeaderValue::from_static("1"));
            r
        }
    }
}

struct Server {
    base: String,
    log: Log,
}

impl Server {
    async fn start() -> Self {
        let log = Log::default();
        let app = Router::new().fallback(handler).with_state(Arc::clone(&log));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, log }
    }

    fn client(&self) -> ReqwestUpstream {
        ReqwestUpstream::new(UpstreamConfig::new(&self.base)).unwrap()
    }

    fn seen(&self) -> Vec<Seen> {
        self.log.lock().unwrap().clone()
    }
}

fn request(method: Method, path: &str) -> UpstreamRequest {
    UpstreamRequest {
        method,
        path: ProxyPath::parse(path).unwrap(),
        query: None,
        headers: vec![],
        body: vec![],
        bearer: AccessToken::new("tok.en".to_owned()).unwrap(),
    }
}

#[tokio::test]
async fn url_final_exacta_con_percent_y_query() {
    let s = Server::start().await;
    let mut req = request(Method::Get, "v1/clientes/a%20b/%C3%A9/x");
    req.query = Some("q=1&r=%C3%A9&x=a+b&vacio=".to_owned());
    let resp = s.client().forward(req).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(
        s.seen()[0].uri,
        "/v1/clientes/a%20b/%C3%A9/x?q=1&r=%C3%A9&x=a+b&vacio="
    );
}

#[tokio::test]
async fn ruta_vacia_sin_query_y_prefijo_de_la_base() {
    let s = Server::start().await;
    s.client().forward(request(Method::Get, "")).await.unwrap();
    let con_prefijo = ReqwestUpstream::new(UpstreamConfig::new(format!("{}/api/v2", s.base))).unwrap();
    con_prefijo
        .forward(request(Method::Get, "items/7"))
        .await
        .unwrap();
    let uris: Vec<_> = s.seen().into_iter().map(|x| x.uri).collect();
    assert_eq!(uris, ["/", "/api/v2/items/7"]);
}

#[tokio::test]
async fn bearer_correcto_y_solo_las_cabeceras_recibidas() {
    let s = Server::start().await;
    let mut req = request(Method::Get, "x");
    req.headers = vec![
        ("x-tenant".to_owned(), "t1".to_owned()),
        ("accept".to_owned(), "application/json".to_owned()),
        ("authorization".to_owned(), "Bearer del-cliente".to_owned()),
        ("host".to_owned(), "evil.example".to_owned()),
    ];
    s.client().forward(req).await.unwrap();
    let seen = &s.seen()[0];
    assert_eq!(seen.header("authorization"), Some("Bearer tok.en"));
    assert_eq!(seen.header("x-tenant"), Some("t1"));
    assert_eq!(seen.header("accept"), Some("application/json"));
    assert!(!seen.header("host").unwrap().contains("evil"));
    let mut nombres: Vec<_> = seen.headers.iter().map(|(k, _)| k.as_str()).collect();
    nombres.sort_unstable();
    assert_eq!(nombres, ["accept", "authorization", "host", "x-tenant"]);
}

#[tokio::test]
async fn metodos_y_cuerpo() {
    let s = Server::start().await;
    let client = s.client();
    for (m, nombre) in [
        (Method::Get, "GET"),
        (Method::Head, "HEAD"),
        (Method::Options, "OPTIONS"),
        (Method::Delete, "DELETE"),
        (Method::Post, "POST"),
        (Method::Put, "PUT"),
        (Method::Patch, "PATCH"),
    ] {
        let mut req = request(m, "m");
        if m.is_unsafe() {
            req.body = format!("cuerpo-{nombre}").into_bytes();
            req.headers
                .push(("content-type".to_owned(), "text/plain".to_owned()));
        }
        client.forward(req).await.unwrap();
    }
    let seen = s.seen();
    assert_eq!(seen.len(), 7);
    for x in &seen {
        if matches!(x.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
            assert_eq!(x.body, format!("cuerpo-{}", x.method).into_bytes());
            assert_eq!(x.header("content-type"), Some("text/plain"));
        } else {
            assert!(x.body.is_empty());
            assert!(x.header("content-length").is_none(), "{x:?}");
        }
    }
    // Un POST sin cuerpo envia content-length: 0.
    client.forward(request(Method::Post, "vacio")).await.unwrap();
    assert_eq!(s.seen()[7].header("content-length"), Some("0"));
}

#[tokio::test]
async fn respuesta_con_estado_cuerpo_y_cabeceras_en_minusculas() {
    let s = Server::start().await;
    let resp = s.client().forward(request(Method::Get, "a")).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"eco:/a");
    assert!(resp.headers.iter().any(|(k, v)| k == "x-eco" && v == "1"));
    assert!(resp.headers.iter().all(|(k, _)| *k == k.to_ascii_lowercase()));
}

#[tokio::test]
async fn set_cookie_llega_al_adaptador_y_las_cabeceras_van_en_minusculas() {
    let s = Server::start().await;
    let resp = s.client().forward(request(Method::Get, "cookies")).await.unwrap();
    let cookies: Vec<_> = resp
        .headers
        .iter()
        .filter(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(cookies, ["a=1; Path=/; HttpOnly", "b=2; Secure"]);
    assert!(resp.headers.iter().any(|(k, v)| k == "x-mixed-case" && v == "v"));
    assert!(resp.headers.iter().all(|(k, _)| *k == k.to_ascii_lowercase()));
}

#[tokio::test]
async fn el_5xx_del_upstream_se_devuelve_tal_cual() {
    let s = Server::start().await;
    let resp = s.client().forward(request(Method::Get, "error")).await.unwrap();
    assert_eq!(resp.status, 500);
    assert_eq!(resp.body, b"fallo");
}

#[tokio::test]
async fn redireccion_no_se_sigue() {
    let s = Server::start().await;
    let resp = s
        .client()
        .forward(request(Method::Get, "redireccion"))
        .await
        .unwrap();
    assert_eq!(resp.status, 302);
    assert!(
        resp.headers
            .iter()
            .any(|(k, v)| k == "location" && v == "/destino")
    );
    assert_eq!(resp.body, b"redirigiendo");
    assert_eq!(s.seen().len(), 1);
}

#[tokio::test]
async fn timeout_total() {
    let s = Server::start().await;
    let client =
        ReqwestUpstream::new(UpstreamConfig::new(&s.base).with_timeout(Duration::from_millis(300))).unwrap();
    assert_eq!(
        client.forward(request(Method::Get, "lento")).await.err(),
        Some(UpstreamError::Timeout)
    );
}

#[tokio::test]
async fn el_timeout_cubre_tambien_la_lectura_del_cuerpo() {
    let s = Server::start().await;
    let client =
        ReqwestUpstream::new(UpstreamConfig::new(&s.base).with_timeout(Duration::from_millis(500))).unwrap();
    assert_eq!(
        client.forward(request(Method::Get, "cuerpo-goteo")).await.err(),
        Some(UpstreamError::Timeout)
    );
}

#[tokio::test]
async fn upstream_caido_es_unavailable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let client = ReqwestUpstream::new(UpstreamConfig::new(base)).unwrap();
    assert_eq!(
        client.forward(request(Method::Get, "x")).await.err(),
        Some(UpstreamError::Unavailable)
    );
}

#[tokio::test]
async fn respuesta_mayor_que_el_limite_es_too_large() {
    let s = Server::start().await;
    let client = ReqwestUpstream::new(UpstreamConfig::new(&s.base).with_max_response_bytes(MIB)).unwrap();
    // Con content-length conocido.
    assert_eq!(
        client.forward(request(Method::Get, "grande")).await.err(),
        Some(UpstreamError::TooLarge)
    );
    // Sin content-length (chunked): se corta en streaming al pasar el tope.
    assert_eq!(
        client.forward(request(Method::Get, "grande-chunked")).await.err(),
        Some(UpstreamError::TooLarge)
    );
    // Exactamente el limite si pasa.
    let ok = client.forward(request(Method::Get, "exacto")).await.unwrap();
    assert_eq!(ok.body.len(), MIB);
}

#[tokio::test]
async fn cuerpo_de_la_peticion_grande() {
    let s = Server::start().await;
    let mut req = request(Method::Post, "subida");
    req.body = vec![b'z'; 3 * MIB];
    s.client().forward(req).await.unwrap();
    assert_eq!(s.seen()[0].body.len(), 3 * MIB);
}

#[test]
fn valida_la_url_base() {
    let ok = |u: &str| ReqwestUpstream::new(UpstreamConfig::new(u)).map(|_| ());
    assert_eq!(ok("https://api.example.com"), Ok(()));
    assert_eq!(ok("https://api.example.com/v1"), Ok(()));
    assert_eq!(ok("https://api.example.com/"), Err(ConfigError::TrailingSlash));
    assert_eq!(ok("https://api.example.com/v1/"), Err(ConfigError::TrailingSlash));
    assert_eq!(ok("ftp://api.example.com"), Err(ConfigError::NotHttps));
    assert_eq!(ok("api.example.com"), Err(ConfigError::InvalidUrl));
    assert_eq!(
        ok("https://u:p@api.example.com"),
        Err(ConfigError::UnexpectedParts)
    );
    assert_eq!(
        ok("https://api.example.com?x=1"),
        Err(ConfigError::UnexpectedParts)
    );
    assert_eq!(ok("https://api.example.com#f"), Err(ConfigError::UnexpectedParts));
    assert_eq!(ok(""), Err(ConfigError::InvalidUrl));
}
