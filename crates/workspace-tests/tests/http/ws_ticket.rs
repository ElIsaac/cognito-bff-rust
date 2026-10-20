//! `/auth/ws-ticket` (§18): boleto de un solo uso para abrir el WebSocket.

use application::ports::WsTicketStore;
use axum::http::StatusCode;
use domain::{IdHash, WsTicketId};

use crate::support::{Env, Req, SESSION_COOKIE, assert_error, hash_of};

async fn pedir(env: &Env, id: &str) -> serde_json::Value {
    let r = env.send(Req::post("/auth/ws-ticket").csrf().sesion(id)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    r.json()
}

/// El boleto tiene la forma `{"ticket","expiresIn":30}` con 43 caracteres base64url y sale
/// sin cache.
#[tokio::test(start_paused = true)]
async fn boleto_con_la_forma_esperada() {
    let env = Env::new();
    let id = env.sesion().await;
    let r = env.send(Req::post("/auth/ws-ticket").csrf().sesion(&id)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("content-type"), Some("application/json"));
    let body = r.json();
    let obj = body.as_object().unwrap();
    assert_eq!(obj.len(), 2, "{body}");
    assert_eq!(obj["expiresIn"], 30);
    let t = obj["ticket"].as_str().unwrap();
    assert_eq!(t.len(), 43);
    assert!(
        t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
}

/// El boleto se guarda por hash (un volcado de la tabla no da boletos usables), ligado a la
/// sesion, y se consume una sola vez.
#[tokio::test(start_paused = true)]
async fn boleto_guardado_por_hash_y_de_un_solo_uso() {
    let env = Env::new();
    let id = env.sesion().await;
    let ticket = pedir(&env, &id).await["ticket"].as_str().unwrap().to_owned();

    let hash = WsTicketId::parse(&ticket).unwrap().hash();
    assert_eq!(env.ports.tickets().keys(), vec![hash.as_str().to_owned()]);
    assert_ne!(hash.as_str(), ticket);
    assert!(
        env.ports
            .tickets()
            .snapshot(&IdHash::from_stored(ticket.clone()))
            .is_none()
    );
    let guardado = env.ports.tickets().snapshot(&hash).unwrap();
    assert_eq!(guardado.session_hash, hash_of(&id));
    assert!(!format!("{guardado:?}").contains(&ticket));

    let tickets = env.ports.tickets();
    assert!(
        tickets
            .consume(&IdHash::from_stored(ticket))
            .await
            .unwrap()
            .is_none()
    );
    assert!(tickets.consume(&hash).await.unwrap().is_some());
    assert!(
        tickets.consume(&hash).await.unwrap().is_none(),
        "replay del boleto"
    );
}

/// Cada peticion da un boleto distinto.
#[tokio::test(start_paused = true)]
async fn cada_boleto_es_distinto() {
    let env = Env::new();
    let id = env.sesion().await;
    let a = pedir(&env, &id).await;
    let b = pedir(&env, &id).await;
    assert_ne!(a["ticket"], b["ticket"]);
    assert_eq!(env.ports.tickets().len(), 2);
}

/// Sin sesion (o con cookie basura) nadie obtiene un boleto: 401 y la cookie se borra.
#[tokio::test(start_paused = true)]
async fn sin_sesion_no_hay_boleto() {
    let env = Env::new();
    for req in [
        Req::post("/auth/ws-ticket").csrf(),
        Req::post("/auth/ws-ticket").csrf().sesion("basura"),
        Req::post("/auth/ws-ticket").csrf().sesion(&"A".repeat(43)),
    ] {
        let r = env.send(req).await;
        assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
        assert!(r.borra_cookie(SESSION_COOKIE));
    }
    assert!(env.ports.tickets().is_empty());
}

/// Tras el logout el mismo cookie ya no emite boletos.
#[tokio::test(start_paused = true)]
async fn tras_logout_no_hay_boleto() {
    let env = Env::new();
    let id = env.sesion().await;
    env.send(Req::post("/auth/logout").csrf().sesion(&id)).await;
    let r = env.send(Req::post("/auth/ws-ticket").csrf().sesion(&id)).await;
    assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    assert!(env.ports.tickets().is_empty());
}
