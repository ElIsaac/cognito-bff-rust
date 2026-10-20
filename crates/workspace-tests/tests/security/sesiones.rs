//! Ciclo de vida de la sesion: logout, expiracion, cookies manipuladas y `last_seen_at`.

use application::AppError;
use application::ports::IdentityProvider;

use crate::common::{Env, hash_of, login, secs, stored};

/// Logout: la sesion se borra, el refresh token se revoca en el IdP y la cookie vieja (que
/// un atacante pudo haber copiado) deja de funcionar.
#[tokio::test(start_paused = true)]
async fn logout_borra_sesion_revoca_refresh_e_invalida_la_cookie() {
    let env = Env::new();
    let cookie = login(&env).await;
    let refresh = stored(&env, &cookie).tokens.refresh;

    let url = env.app.logout(Some(&cookie)).await.unwrap();
    assert_eq!(url, env.ports.idp().logout_url());
    assert!(env.ports.sessions().is_empty());
    assert_eq!(
        env.ports.idp().revoked(),
        vec![refresh.expose_secret().to_owned()]
    );
    assert!(!env.ports.idp().is_refresh_valid(&refresh));

    assert_eq!(
        env.app.current_user(Some(&cookie)).await.unwrap_err(),
        AppError::Unauthorized
    );
    assert_eq!(env.ports.idp().refresh_calls(), 0);
}

/// Logout idempotente: sin cookie, con cookie malformada o repetido, siempre devuelve la
/// URL de logout y no revoca nada.
#[tokio::test(start_paused = true)]
async fn logout_es_idempotente() {
    let env = Env::new();
    let esperado = env.ports.idp().logout_url();
    assert_eq!(env.app.logout(None).await.unwrap(), esperado);
    assert_eq!(env.app.logout(Some("basura")).await.unwrap(), esperado);

    let cookie = login(&env).await;
    assert_eq!(env.app.logout(Some(&cookie)).await.unwrap(), esperado);
    assert_eq!(env.app.logout(Some(&cookie)).await.unwrap(), esperado);
    assert_eq!(env.ports.idp().revoke_calls(), 1);
}

/// Un fallo del IdP al revocar no impide cerrar la sesion local.
#[tokio::test(start_paused = true)]
async fn logout_borra_la_sesion_aunque_la_revocacion_falle() {
    let env = Env::new();
    let cookie = login(&env).await;
    // Refresh ya revocado por otro lado: el fake no falla, pero la sesion igual se cierra.
    let refresh = stored(&env, &cookie).tokens.refresh;
    env.ports.idp().revoke(&refresh).await.unwrap();
    env.app.logout(Some(&cookie)).await.unwrap();
    assert!(env.ports.sessions().is_empty());
}

/// Sesion robada y abandonada: tras 12 h sin actividad se rechaza y se borra del almacen.
#[tokio::test(start_paused = true)]
async fn inactividad_mayor_a_12_horas_cierra_la_sesion() {
    let env = Env::new();
    let cookie = login(&env).await;
    env.advance_secs(12 * 3600 - 1).await;
    // Aun vigente (y de paso la usa: reinicia el contador de inactividad).
    env.ports.idp().set_access_ttl(secs(30 * 24 * 3600));
    env.app.current_user(Some(&cookie)).await.unwrap();

    env.advance_secs(12 * 3600).await;
    assert_eq!(
        env.app.current_user(Some(&cookie)).await.unwrap_err(),
        AppError::Unauthorized
    );
    assert!(env.ports.sessions().snapshot(&hash_of(&cookie)).is_none());
    assert!(env.ports.sessions().is_empty());
}

/// Sesion con `ttl` ya pasado que sigue en la tabla (el borrado por TTL de DynamoDB es
/// diferido): se rechaza y se borra en el acto, sin llamar al IdP.
#[tokio::test(start_paused = true)]
async fn sesion_vencida_aun_en_la_tabla_se_rechaza_y_borra() {
    let env = Env::new();
    let cookie = login(&env).await;
    let ttl = env.ports.sessions().ttl_of(&hash_of(&cookie)).unwrap();
    env.advance_secs(12 * 3600 + 1).await;
    assert!(env.ports.clock().now() > ttl);
    assert!(
        env.ports.sessions().snapshot(&hash_of(&cookie)).is_some(),
        "sigue en la tabla"
    );

    assert_eq!(
        env.app.current_user(Some(&cookie)).await.unwrap_err(),
        AppError::Unauthorized
    );
    assert!(env.ports.sessions().is_empty());
    assert_eq!(env.ports.idp().refresh_calls(), 0);
}

/// Sesion inmortal: usarla cada hora (refrescando el access token) no la extiende mas alla
/// de la vida absoluta de 7 dias.
#[tokio::test(start_paused = true)]
async fn vida_absoluta_se_respeta_aunque_haya_actividad() {
    let env = Env::new();
    let cookie = login(&env).await;
    for hora in 1..(7 * 24) {
        env.advance_secs(3600).await;
        env.app
            .current_user(Some(&cookie))
            .await
            .unwrap_or_else(|e| panic!("hora {hora}: {e:?}"));
    }
    assert_eq!(
        env.ports.idp().refresh_calls(),
        7 * 24 - 1,
        "access refrescado cada hora"
    );

    env.advance_secs(3600).await;
    assert_eq!(
        env.app.current_user(Some(&cookie)).await.unwrap_err(),
        AppError::Unauthorized
    );
    assert!(env.ports.sessions().is_empty());
}

/// Cookies manipuladas: vacia, truncada, alargada, con caracteres fuera del alfabeto,
/// con bits sobrantes no canonicos, bien formada pero inexistente, enorme o con CRLF. Todas
/// `Unauthorized`, sin tocar el IdP ni el almacen.
#[tokio::test(start_paused = true)]
async fn cookies_manipuladas_son_unauthorized() {
    let env = Env::new();
    let valida = login(&env).await;
    let escrituras = env.ports.sessions().writes();

    let mut cambiado = valida.clone().into_bytes();
    cambiado[10] = if cambiado[10] == b'A' { b'B' } else { b'A' };
    let mut no_canonica = valida.clone().into_bytes();
    let ultimo = no_canonica.len() - 1;
    no_canonica[ultimo] = if no_canonica[ultimo] == b'_' { b'-' } else { b'_' };

    let casos: Vec<String> = vec![
        String::new(),
        valida[..42].to_owned(),
        valida[..1].to_owned(),
        format!("{valida}A"),
        format!("{valida}="),
        "!".repeat(43),
        "é".repeat(22),
        format!("{} ", &valida[..42]),
        format!("{}\r\nX: y", &valida[..30]),
        format!("{}\0", &valida[..42]),
        "A".repeat(43),
        "A".repeat(10_000),
        String::from_utf8(cambiado).unwrap(),
        String::from_utf8(no_canonica).unwrap(),
        valida.to_uppercase(),
        "undefined".to_owned(),
    ];
    for c in &casos {
        assert_eq!(
            env.app.current_user(Some(c)).await.unwrap_err(),
            AppError::Unauthorized,
            "cookie {c:?}"
        );
    }
    assert_eq!(
        env.app.current_user(None).await.unwrap_err(),
        AppError::Unauthorized
    );
    assert_eq!(env.ports.sessions().writes(), escrituras);
    assert_eq!(env.ports.sessions().len(), 1, "la sesion legitima sigue intacta");
    assert_eq!(env.ports.idp().refresh_calls(), 0);
    env.app.current_user(Some(&valida)).await.unwrap();
}

/// `last_seen_at`: un GET dentro de 5 minutos no escribe (la version no cambia); pasados
/// los 5 minutos si, y renueva el `ttl` de inactividad.
#[tokio::test(start_paused = true)]
async fn last_seen_solo_se_escribe_pasados_5_minutos() {
    let env = Env::new();
    env.ports.idp().set_access_ttl(secs(30 * 24 * 3600));
    let cookie = login(&env).await;
    let v0 = stored(&env, &cookie).version;
    let escrituras = env.ports.sessions().writes();

    env.advance_secs(299).await;
    env.app.current_user(Some(&cookie)).await.unwrap();
    env.app.current_user(Some(&cookie)).await.unwrap();
    assert_eq!(stored(&env, &cookie).version, v0);
    assert_eq!(env.ports.sessions().writes(), escrituras);

    env.advance_secs(1).await;
    env.app.current_user(Some(&cookie)).await.unwrap();
    let s = stored(&env, &cookie);
    assert_eq!(s.version, v0.next());
    assert_eq!(s.last_seen_at, env.ports.clock().now());
    assert_eq!(env.ports.sessions().writes(), escrituras + 1);
    assert_eq!(
        env.ports.sessions().ttl_of(&hash_of(&cookie)),
        Some(env.ports.clock().now().saturating_add(secs(12 * 3600)))
    );

    env.app.current_user(Some(&cookie)).await.unwrap();
    assert_eq!(
        env.ports.sessions().writes(),
        escrituras + 1,
        "otra vez dentro de 5 min"
    );
}
