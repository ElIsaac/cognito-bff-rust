//! Refresh concurrente con lease: una sola llamada al IdP, lease huerfano, `invalid_grant`,
//! fallos transitorios y rotacion.

use std::collections::BTreeSet;
use std::time::Duration;

use application::AppError;
use application::ports::{AdapterError, IdentityProvider, IdpError, LeaseOutcome, SessionRepository};

use crate::common::{Env, hash_of, login, secs, stored};

const TRANSITORIO: IdpError = IdpError::Adapter(AdapterError::Transient);

/// Login y avance del reloj hasta que el access token esta a 30 s de vencer (dentro del
/// umbral de 60 s, pero aun valido).
async fn login_a_punto_de_vencer(env: &Env) -> String {
    let cookie = login(env).await;
    env.advance_secs(3600 - 30).await;
    cookie
}

async fn n_tareas_simultaneas(env: &Env, cookie: &str, n: usize) -> Vec<Result<domain::Session, AppError>> {
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let app = env.app.clone();
            let cookie = cookie.to_owned();
            tokio::spawn(async move { app.ensure_fresh_session(Some(&cookie)).await })
        })
        .collect();
    let mut out = Vec::with_capacity(n);
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}

async fn refresh_concurrente(n: usize, exigir_carrera: bool) {
    let env = Env::new();
    // Sin avanzar el reloj (el test de hilos reales corre en tiempo real): el access token
    // nace con 30 s de vida y el refresh emite uno de 1 h.
    env.ports.idp().set_access_ttl(secs(30));
    let cookie = login(&env).await;
    env.ports.idp().set_access_ttl(secs(3600));
    let viejo = stored(&env, &cookie).tokens.access.expose_secret().to_owned();
    env.ports.idp().set_refresh_latency(Duration::from_millis(200));

    let resultados = n_tareas_simultaneas(&env, &cookie, n).await;

    assert_eq!(
        env.ports.idp().refresh_calls(),
        1,
        "exactamente un refresh con {n} tareas"
    );
    let tokens: BTreeSet<String> = resultados
        .into_iter()
        .map(|r| {
            r.expect("todas deben responder Ok")
                .tokens
                .access
                .expose_secret()
                .to_owned()
        })
        .collect();
    assert_eq!(tokens.len(), 1, "todas ven el mismo access token nuevo");
    assert!(!tokens.contains(&viejo));
    let s = stored(&env, &cookie);
    assert_eq!(tokens.first().unwrap(), s.tokens.access.expose_secret());
    assert_eq!(s.refresh_lock_until, None);
    assert!(
        !exigir_carrera || env.ports.sessions().lease_conflicts() > 0,
        "la carrera por el lease debe haber ocurrido de verdad"
    );
}

/// Tormenta de refresh: 20 peticiones simultaneas con el access token por vencer no deben
/// hacer 20 refresh (agotaria el rate limit de Cognito y, con rotacion, invalidaria
/// tokens): una gana el lease, el resto espera y relee.
#[tokio::test(start_paused = true)]
async fn refresh_con_20_tareas_llama_una_sola_vez() {
    refresh_concurrente(20, true).await;
}

/// Igual que el anterior con 50 tareas.
#[tokio::test(start_paused = true)]
async fn refresh_con_50_tareas_llama_una_sola_vez() {
    refresh_concurrente(50, true).await;
}

/// Igual que el anterior con 200 tareas.
#[tokio::test(start_paused = true)]
async fn refresh_con_200_tareas_llama_una_sola_vez() {
    refresh_concurrente(200, true).await;
}

/// Igual, pero con hilos reales y tiempo real (carreras genuinas entre hilos del runtime).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_con_50_tareas_en_hilos_reales_llama_una_sola_vez() {
    refresh_concurrente(50, false).await;
}

/// Lease huerfano: una invocacion tomo el lease y murio sin liberarlo. Otra peticion espera
/// (no llama al IdP mientras el lease siga vigente) y, tras 10 s simulados, lo toma y
/// refresca una sola vez.
#[tokio::test(start_paused = true)]
async fn lease_huerfano_se_recupera_tras_10_segundos() {
    let env = Env::with(|c| c.refresh_retry.max_attempts = 40);
    let cookie = login_a_punto_de_vencer(&env).await;
    let hash = hash_of(&cookie);
    let version = stored(&env, &cookie).version;
    let t0 = env.ports.clock().now();
    let lease = env
        .ports
        .sessions()
        .acquire_refresh_lease(&hash, version, t0, t0.saturating_add(secs(10)))
        .await
        .unwrap();
    assert_eq!(
        lease,
        LeaseOutcome::Acquired {
            version: version.next()
        }
    );

    let app = env.app.clone();
    let c = cookie.clone();
    let tarea = tokio::spawn(async move { app.ensure_fresh_session(Some(&c)).await });
    env.advance_secs(5).await;
    assert!(!tarea.is_finished(), "debe seguir esperando el lease ajeno");
    assert_eq!(env.ports.idp().refresh_calls(), 0);

    let s = tarea.await.unwrap().unwrap();
    assert_eq!(env.ports.idp().refresh_calls(), 1);
    assert!(env.ports.clock().now().saturating_since(t0) >= secs(10));
    let guardada = stored(&env, &cookie);
    assert_eq!(
        s.tokens.access.expose_secret(),
        guardada.tokens.access.expose_secret()
    );
    assert_eq!(guardada.refresh_lock_until, None);
    assert_eq!(guardada.version, version.next().next().next());
}

/// Si los reintentos se agotan antes de que el lease ajeno caduque: `Busy` (503 con
/// `Retry-After`), sin llamar al IdP y sin pisar el lease ajeno.
#[tokio::test(start_paused = true)]
async fn lease_ajeno_vigente_agota_reintentos_en_busy() {
    for max_attempts in [1, 2, 8] {
        let env = Env::with(|c| c.refresh_retry.max_attempts = max_attempts);
        let cookie = login_a_punto_de_vencer(&env).await;
        let version = stored(&env, &cookie).version;
        let t0 = env.ports.clock().now();
        let hasta = t0.saturating_add(secs(10));
        env.ports
            .sessions()
            .acquire_refresh_lease(&hash_of(&cookie), version, t0, hasta)
            .await
            .unwrap();

        let r = env.app.ensure_fresh_session(Some(&cookie)).await;
        assert_eq!(r.unwrap_err(), AppError::Busy, "max_attempts {max_attempts}");
        assert_eq!(env.ports.idp().refresh_calls(), 0);
        let s = stored(&env, &cookie);
        assert_eq!(s.refresh_lock_until, Some(hasta), "el lease ajeno no se toca");
        assert_eq!(s.version, version.next());
    }
}

/// `invalid_grant` (refresh revocado o caducado): la sesion se borra, la respuesta es
/// `Unauthorized` y el IdP recibe exactamente una llamada (sin bucles de reintento).
#[tokio::test(start_paused = true)]
async fn invalid_grant_borra_la_sesion_con_una_sola_llamada() {
    let env = Env::new();
    let cookie = login_a_punto_de_vencer(&env).await;
    env.ports.idp().fail_refresh(IdpError::InvalidGrant, 1);

    let r = env.app.ensure_fresh_session(Some(&cookie)).await;
    assert_eq!(r.unwrap_err(), AppError::Unauthorized);
    assert_eq!(env.ports.idp().refresh_calls(), 1);
    assert!(env.ports.sessions().is_empty());

    let r = env.app.ensure_fresh_session(Some(&cookie)).await;
    assert_eq!(r.unwrap_err(), AppError::Unauthorized);
    assert_eq!(
        env.ports.idp().refresh_calls(),
        1,
        "sin sesion no se vuelve a llamar"
    );
}

/// Un ID token refrescado de otro usuario (`sub` distinto) se trata como rechazado: la
/// sesion se destruye, no se guardan los tokens nuevos y no se vuelve a llamar al IdP.
#[tokio::test(start_paused = true)]
async fn refresh_con_otro_sub_destruye_la_sesion() {
    let env = Env::new();
    let cookie = login_a_punto_de_vencer(&env).await;
    let otro = domain::UserInfo::new(
        domain::Subject::new("usuario-ajeno".to_owned()).unwrap(),
        None,
        None,
        vec![],
    );
    env.ports.idp().set_refresh_user(Some(otro));

    let r = env.app.ensure_fresh_session(Some(&cookie)).await;
    assert_eq!(r.unwrap_err(), AppError::Unauthorized);
    assert_eq!(env.ports.idp().refresh_calls(), 1);
    assert!(env.ports.sessions().is_empty());
    let r = env.app.ensure_fresh_session(Some(&cookie)).await;
    assert_eq!(r.unwrap_err(), AppError::Unauthorized);
    assert_eq!(env.ports.idp().refresh_calls(), 1);
}

/// El mismo `sub` en el ID token refrescado si actualiza los claims de la sesion.
#[tokio::test(start_paused = true)]
async fn refresh_con_el_mismo_sub_actualiza_los_claims() {
    let env = Env::new();
    let cookie = login_a_punto_de_vencer(&env).await;
    let nuevo = domain::UserInfo::new(
        domain::Subject::new("user-1".to_owned()).unwrap(),
        None,
        Some("Ana Maria".to_owned()),
        vec![],
    );
    env.ports.idp().set_refresh_user(Some(nuevo));
    let s = env.app.ensure_fresh_session(Some(&cookie)).await.unwrap();
    assert_eq!(s.user.name(), Some("Ana Maria"));
    assert_eq!(stored(&env, &cookie).user.name(), Some("Ana Maria"));
}

/// Refresh token revocado en el IdP (p. ej. "cerrar sesion en todos lados"): mismo
/// resultado, de forma natural y no por un fallo programado.
#[tokio::test(start_paused = true)]
async fn refresh_revocado_en_el_idp_cierra_la_sesion() {
    let env = Env::new();
    let cookie = login_a_punto_de_vencer(&env).await;
    let refresh = stored(&env, &cookie).tokens.refresh;
    env.ports.idp().revoke(&refresh).await.unwrap();

    let r = env.app.ensure_fresh_session(Some(&cookie)).await;
    assert_eq!(r.unwrap_err(), AppError::Unauthorized);
    assert_eq!(env.ports.idp().refresh_calls(), 1);
    assert!(env.ports.sessions().is_empty());
}

/// Fallo transitorio del IdP con el access token aun valido: se sirve el token viejo (el
/// usuario no ve el fallo) y el lease queda liberado para el siguiente intento.
#[tokio::test(start_paused = true)]
async fn fallo_transitorio_con_access_valido_sirve_el_token_viejo() {
    let env = Env::new();
    let cookie = login_a_punto_de_vencer(&env).await;
    let antes = stored(&env, &cookie);
    env.ports.idp().fail_refresh(TRANSITORIO, 1);

    let s = env.app.ensure_fresh_session(Some(&cookie)).await.unwrap();
    assert_eq!(
        s.tokens.access.expose_secret(),
        antes.tokens.access.expose_secret()
    );
    assert_eq!(env.ports.idp().refresh_calls(), 1);
    let guardada = stored(&env, &cookie);
    assert_eq!(guardada.refresh_lock_until, None, "lease liberado");
    assert_eq!(guardada.version, antes.version.next().next());

    let s = env.app.ensure_fresh_session(Some(&cookie)).await.unwrap();
    assert_ne!(
        s.tokens.access.expose_secret(),
        antes.tokens.access.expose_secret()
    );
    assert_eq!(env.ports.idp().refresh_calls(), 2);
}

/// IdP caido y access token ya vencido: no se sirve un token vencido; responde `Busy` tras
/// UNA sola llamada (sin amplificar hacia un proveedor caido), la sesion NO se borra y el
/// lease queda liberado.
#[tokio::test(start_paused = true)]
async fn fallo_transitorio_persistente_con_access_vencido_termina_en_busy() {
    let env = Env::new();
    let cookie = login(&env).await;
    env.advance_secs(3600 + 10).await;
    env.ports.idp().fail_refresh(TRANSITORIO, 100);

    let r = env.app.ensure_fresh_session(Some(&cookie)).await;
    assert_eq!(r.unwrap_err(), AppError::Busy);
    assert_eq!(
        env.ports.idp().refresh_calls(),
        1,
        "sin reintentos hacia un IdP caido"
    );
    let s = stored(&env, &cookie);
    assert_eq!(s.refresh_lock_until, None);
}

/// Rotacion de refresh tokens: el guardado tras el refresh es el nuevo y el viejo queda
/// invalido en el IdP (reutilizarlo falla).
#[tokio::test(start_paused = true)]
async fn rotacion_guarda_el_refresh_nuevo_e_invalida_el_viejo() {
    let env = Env::new();
    env.ports.idp().set_rotate_refresh(true);
    let cookie = login_a_punto_de_vencer(&env).await;
    let viejo = stored(&env, &cookie).tokens.refresh;

    env.app.ensure_fresh_session(Some(&cookie)).await.unwrap();
    let nuevo = stored(&env, &cookie).tokens.refresh;
    assert_ne!(nuevo.expose_secret(), viejo.expose_secret());
    assert!(env.ports.idp().is_refresh_valid(&nuevo));
    assert!(!env.ports.idp().is_refresh_valid(&viejo));
    assert_eq!(
        env.ports.idp().refresh(&viejo).await.unwrap_err(),
        IdpError::InvalidGrant
    );

    env.advance_secs(3600 - 30).await;
    env.app.ensure_fresh_session(Some(&cookie)).await.unwrap();
    assert_ne!(
        stored(&env, &cookie).tokens.refresh.expose_secret(),
        nuevo.expose_secret()
    );
}

/// Sin rotacion el refresh token guardado no cambia.
#[tokio::test(start_paused = true)]
async fn sin_rotacion_el_refresh_token_se_conserva() {
    let env = Env::new();
    let cookie = login_a_punto_de_vencer(&env).await;
    let antes = stored(&env, &cookie).tokens.refresh;
    env.app.ensure_fresh_session(Some(&cookie)).await.unwrap();
    assert_eq!(
        stored(&env, &cookie).tokens.refresh.expose_secret(),
        antes.expose_secret()
    );
}

/// Rotacion con tormenta: 20 tareas simultaneas rotan una sola vez y el refresh guardado es
/// el vigente en el IdP (nadie quedo con un refresh invalidado).
#[tokio::test(start_paused = true)]
async fn rotacion_con_tareas_simultaneas_deja_el_refresh_vigente() {
    let env = Env::new();
    env.ports.idp().set_rotate_refresh(true);
    let cookie = login_a_punto_de_vencer(&env).await;
    env.ports.idp().set_refresh_latency(Duration::from_millis(200));

    let resultados = n_tareas_simultaneas(&env, &cookie, 20).await;
    assert!(resultados.iter().all(Result::is_ok));
    assert_eq!(env.ports.idp().refresh_calls(), 1);
    assert!(
        env.ports
            .idp()
            .is_refresh_valid(&stored(&env, &cookie).tokens.refresh)
    );
}

/// Un logout concurrente con un refresh en vuelo no resucita la sesion: la escritura final
/// del refresh no encuentra la sesion y la peticion responde `Unauthorized`.
#[tokio::test(start_paused = true)]
async fn logout_durante_un_refresh_no_resucita_la_sesion() {
    let env = Env::new();
    let cookie = login_a_punto_de_vencer(&env).await;
    env.ports.idp().set_refresh_latency(Duration::from_millis(200));

    let app = env.app.clone();
    let c = cookie.clone();
    let refresco = tokio::spawn(async move { app.ensure_fresh_session(Some(&c)).await });
    env.advance(Duration::from_millis(50)).await;
    env.app.logout(Some(&cookie)).await.unwrap();

    assert_eq!(refresco.await.unwrap().unwrap_err(), AppError::Unauthorized);
    assert!(env.ports.sessions().is_empty());
}
