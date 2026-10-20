//! Boleto de WebSocket (plan 18).

use application::AppError;
use application::ports::WsTicketStore;
use domain::IdHash;

use crate::common::{Env, TENANT, hash_of, login, secs, user};

/// Boleto sin sesion: nadie sin sesion valida (o con cookie falsa) obtiene un boleto.
#[tokio::test(start_paused = true)]
async fn sin_sesion_no_hay_boleto() {
    let env = Env::new();
    let desconocida = "A".repeat(43);
    for cookie in [None, Some("basura"), Some(desconocida.as_str())] {
        assert_eq!(
            env.app.issue_ws_ticket(cookie).await.unwrap_err(),
            AppError::Unauthorized
        );
    }
    assert!(env.ports.tickets().is_empty());
}

/// El boleto se guarda por su hash (un volcado de la tabla no da boletos usables), es de un
/// solo uso, vence a los 30 s y lleva el `session_hash` y los atributos del usuario.
#[tokio::test(start_paused = true)]
async fn boleto_guardado_por_hash_de_un_solo_uso() {
    let env = Env::new();
    let cookie = login(&env).await;
    let issued = env.app.issue_ws_ticket(Some(&cookie)).await.unwrap();
    assert_eq!(issued.expires_in, secs(30));

    let plano = issued.ticket.expose_secret();
    let hash = issued.ticket.hash();
    assert_eq!(env.ports.tickets().keys(), vec![hash.as_str().to_owned()]);
    assert_ne!(hash.as_str(), plano);
    assert!(
        env.ports
            .tickets()
            .snapshot(&IdHash::from_stored(plano.clone()))
            .is_none()
    );

    let guardado = env.ports.tickets().snapshot(&hash).unwrap();
    assert_eq!(guardado.session_hash, hash_of(&cookie));
    assert_eq!(guardado.user, user());
    assert_eq!(
        guardado
            .user
            .attributes()
            .get("custom:tenant_id")
            .map(String::as_str),
        Some(TENANT)
    );
    assert!(!format!("{guardado:?}").contains(&plano));
    assert_eq!(
        env.ports.tickets().ttl_of(&hash),
        Some(guardado.created_at.saturating_add(secs(30)))
    );
    assert_eq!(guardado.created_at, env.ports.clock().now());

    let tickets = env.ports.tickets();
    assert!(
        tickets
            .consume(&IdHash::from_stored(plano))
            .await
            .unwrap()
            .is_none()
    );
    assert!(tickets.consume(&hash).await.unwrap().is_some());
    assert!(
        tickets.consume(&hash).await.unwrap().is_none(),
        "segundo uso: replay"
    );
}

/// Cada peticion recibe un boleto distinto (no hay boletos predecibles ni reutilizados).
#[tokio::test(start_paused = true)]
async fn cada_boleto_es_distinto() {
    let env = Env::new();
    let cookie = login(&env).await;
    let a = env.app.issue_ws_ticket(Some(&cookie)).await.unwrap();
    let b = env.app.issue_ws_ticket(Some(&cookie)).await.unwrap();
    assert_ne!(a.ticket.expose_secret(), b.ticket.expose_secret());
    assert_eq!(env.ports.tickets().len(), 2);
}
