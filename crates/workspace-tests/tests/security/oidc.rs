//! Flujo OIDC: `state`, PKCE, `nonce`, replay, expiracion del login en curso y fijacion.

use application::ports::{AuthorizationRequest, IdentityProvider, IdpError};
use application::{AppError, CallbackParams, LoginError, StartLoginOutcome};
use domain::{CodeVerifier, Nonce, State};

use crate::common::{Env, callback, hash_of, login, secs, start, stored, user};

/// Camino feliz: login completo y lectura del usuario. Base contra la que se comparan
/// todos los ataques de abajo.
#[tokio::test(start_paused = true)]
async fn flujo_completo_feliz() {
    let env = Env::new();
    let p = start(&env, Some("/dashboard")).await;
    assert!(p.url.starts_with("https://idp.test/oauth2/authorize?"));
    let code = env.ports.idp().issue_code(&p.state, user());

    let done = env
        .app
        .complete_login(Some(&p.cookie), callback(&code, &p.state), None)
        .await
        .unwrap();
    assert_eq!(done.return_to.as_str(), "/dashboard");
    assert_eq!(done.max_age, secs(7 * 24 * 3600));
    assert!(
        env.ports.pending().is_empty(),
        "el login en curso debe consumirse"
    );

    let cookie = done.session_id.expose_secret();
    assert_eq!(env.app.current_user(Some(&cookie)).await.unwrap(), user());
    let s = stored(&env, &cookie);
    let now = env.ports.clock().now();
    assert_eq!(s.created_at, now);
    assert_eq!(s.version, domain::Version::INITIAL);
    assert_eq!(
        env.ports.sessions().ttl_of(&hash_of(&cookie)),
        Some(now.saturating_add(secs(12 * 3600))),
        "ttl = min(absoluta, inactividad)"
    );
}

/// Login CSRF / callback forjado: sin `state` en la query el callback se rechaza y no se
/// crea sesion, aunque el `code` sea legitimo.
#[tokio::test(start_paused = true)]
async fn state_ausente_se_rechaza() {
    let env = Env::new();
    let p = start(&env, None).await;
    let code = env.ports.idp().issue_code(&p.state, user());
    let params = CallbackParams {
        code: Some(code),
        state: None,
        error: None,
    };
    let r = env.app.complete_login(Some(&p.cookie), params, None).await;
    assert_eq!(r.unwrap_err(), LoginError::InvalidState);
    assert!(env.ports.sessions().is_empty());
    assert_eq!(
        env.ports.idp().exchange_calls(),
        0,
        "no debe llegar a canjear el code"
    );
}

/// `state` inventado (malformado, vacio o bien formado pero ajeno): se rechaza sin canjear.
#[tokio::test(start_paused = true)]
async fn state_invalido_se_rechaza() {
    let ajeno = domain::State::from_bytes([9; 32]).expose_secret();
    for state in ["", "abc", "%00", &"A".repeat(43), &"A".repeat(10_000), &ajeno] {
        let env = Env::new();
        let p = start(&env, None).await;
        let code = env.ports.idp().issue_code(&p.state, user());
        let r = env
            .app
            .complete_login(Some(&p.cookie), callback(&code, state), None)
            .await;
        assert_eq!(r.unwrap_err(), LoginError::InvalidState, "state {state:?}");
        assert!(env.ports.sessions().is_empty());
        assert_eq!(env.ports.idp().exchange_calls(), 0);
    }
}

/// Mezcla de logins: la cookie pending de A con el `state` (y un code legitimo) de B. Un
/// atacante que fuerza su propio `state` en el navegador de la victima no consigue sesion.
#[tokio::test(start_paused = true)]
async fn state_de_otro_pending_se_rechaza() {
    let env = Env::new();
    let a = start(&env, None).await;
    let b = start(&env, None).await;
    let code_b = env.ports.idp().issue_code(&b.state, user());
    let r = env
        .app
        .complete_login(Some(&a.cookie), callback(&code_b, &b.state), None)
        .await;
    assert_eq!(r.unwrap_err(), LoginError::InvalidState);
    assert!(env.ports.sessions().is_empty());
    assert_eq!(env.ports.idp().exchange_calls(), 0);
}

/// Callback sin cookie pending (o con una cookie malformada o desconocida): sin sesion.
#[tokio::test(start_paused = true)]
async fn callback_sin_cookie_pending_se_rechaza() {
    let env = Env::new();
    let p = start(&env, None).await;
    let code = env.ports.idp().issue_code(&p.state, user());

    let desconocida = "A".repeat(43);
    let casos = [
        (None, LoginError::MissingPending),
        (Some(""), LoginError::MissingPending),
        (Some("basura"), LoginError::MissingPending),
        (Some(desconocida.as_str()), LoginError::InvalidState),
    ];
    for (cookie, esperado) in casos {
        let r = env
            .app
            .complete_login(cookie, callback(&code, &p.state), None)
            .await;
        assert_eq!(r.unwrap_err(), esperado, "cookie {cookie:?}");
    }
    assert!(env.ports.sessions().is_empty());
    assert_eq!(env.ports.pending().len(), 1, "el pending real no se toco");
}

/// Replay del callback (boton atras, enlace reenviado, atacante con la URL): el pending ya
/// fue consumido, asi que el mismo `code`+`state` falla y no hay una segunda sesion.
#[tokio::test(start_paused = true)]
async fn replay_del_callback_falla() {
    let env = Env::new();
    let p = start(&env, None).await;
    let code = env.ports.idp().issue_code(&p.state, user());
    env.app
        .complete_login(Some(&p.cookie), callback(&code, &p.state), None)
        .await
        .unwrap();

    let r = env
        .app
        .complete_login(Some(&p.cookie), callback(&code, &p.state), None)
        .await;
    assert_eq!(r.unwrap_err(), LoginError::InvalidState);
    assert_eq!(env.ports.sessions().len(), 1);
    assert_eq!(env.ports.idp().exchange_calls(), 1);
}

/// Un `code` ya canjeado no sirve en otro login: PKCE (verifier distinto) y un solo uso.
#[tokio::test(start_paused = true)]
async fn code_reutilizado_en_otro_login_falla() {
    let env = Env::new();
    let a = start(&env, None).await;
    let code_a = env.ports.idp().issue_code(&a.state, user());
    env.app
        .complete_login(Some(&a.cookie), callback(&code_a, &a.state), None)
        .await
        .unwrap();

    let b = start(&env, None).await;
    let r = env
        .app
        .complete_login(Some(&b.cookie), callback(&code_a, &b.state), None)
        .await;
    assert_eq!(r.unwrap_err(), LoginError::ExchangeFailed);
    assert_eq!(env.ports.sessions().len(), 1, "solo la sesion del login legitimo");
}

/// Un `code` interceptado y canjeado con el `code_verifier` de otro login (PKCE) se
/// rechaza: sin el verifier original el code robado no vale.
#[tokio::test(start_paused = true)]
async fn code_con_verifier_ajeno_falla() {
    let env = Env::new();
    let a = start(&env, None).await;
    let code_a = env.ports.idp().issue_code(&a.state, user());
    let b = start(&env, None).await;
    let pending_b = env
        .ports
        .pending()
        .snapshot(&domain::PendingId::parse(&b.cookie).unwrap().hash())
        .unwrap();

    let r = env
        .ports
        .idp()
        .exchange_code(
            &domain::AuthCode::new(code_a).unwrap(),
            &pending_b.code_verifier,
            &pending_b.nonce,
        )
        .await;
    assert_eq!(r.unwrap_err(), IdpError::InvalidGrant);
}

/// El fake del IdP aplica PKCE y un solo uso como Cognito: verifier correcto una vez,
/// segundo canje `InvalidGrant`, nonce distinto `TokenRejected`.
#[tokio::test(start_paused = true)]
async fn idp_fake_verifica_pkce_un_solo_uso_y_nonce() {
    let env = Env::new();
    let idp = env.ports.idp();
    let verifier = CodeVerifier::parse(&"v".repeat(43)).unwrap();
    let req = AuthorizationRequest {
        state: State::from_bytes([1; 32]),
        nonce: Nonce::from_bytes([2; 32]),
        code_challenge: verifier.challenge(),
    };
    let state = req.state.expose_secret();
    idp.authorization_url(&req);

    let code = domain::AuthCode::new(idp.issue_code(&state, user())).unwrap();
    let malo = CodeVerifier::parse(&"w".repeat(43)).unwrap();
    assert_eq!(
        idp.exchange_code(&code, &malo, &req.nonce).await.unwrap_err(),
        IdpError::InvalidGrant,
        "verifier incorrecto"
    );
    assert_eq!(
        idp.exchange_code(&code, &verifier, &req.nonce).await.unwrap_err(),
        IdpError::InvalidGrant,
        "el intento fallido ya consumio el code"
    );

    let code = domain::AuthCode::new(idp.issue_code(&state, user())).unwrap();
    idp.exchange_code(&code, &verifier, &req.nonce).await.unwrap();
    assert_eq!(
        idp.exchange_code(&code, &verifier, &req.nonce).await.unwrap_err(),
        IdpError::InvalidGrant,
        "segundo uso"
    );

    let code = domain::AuthCode::new(idp.issue_code(&state, user())).unwrap();
    let otro = Nonce::from_bytes([3; 32]);
    assert_eq!(
        idp.exchange_code(&code, &verifier, &otro).await.unwrap_err(),
        IdpError::TokenRejected,
        "nonce distinto"
    );
}

/// ID token reutilizado/forjado: el IdP firma un `nonce` distinto al de este login. El
/// canje falla (`ExchangeFailed`) y no se crea sesion.
#[tokio::test(start_paused = true)]
async fn nonce_distinto_no_crea_sesion() {
    let env = Env::new();
    let p = start(&env, None).await;
    let otro = Nonce::from_bytes([7; 32]).expose_secret();
    let code = env.ports.idp().issue_code_with_nonce(&p.state, user(), &otro);
    let r = env
        .app
        .complete_login(Some(&p.cookie), callback(&code, &p.state), None)
        .await;
    assert_eq!(r.unwrap_err(), LoginError::ExchangeFailed);
    assert!(env.ports.sessions().is_empty());
}

/// `error=access_denied` del callback: `AccessDenied`, sin sesion y con el pending
/// consumido.
#[tokio::test(start_paused = true)]
async fn error_access_denied_no_crea_sesion() {
    let env = Env::new();
    let p = start(&env, None).await;
    let params = CallbackParams {
        code: None,
        state: Some(p.state.clone()),
        error: Some("access_denied".to_owned()),
    };
    let r = env.app.complete_login(Some(&p.cookie), params, None).await;
    assert_eq!(r.unwrap_err(), LoginError::AccessDenied);
    assert!(env.ports.sessions().is_empty());
    assert!(env.ports.pending().is_empty());
}

/// Un `error` desconocido se traduce a `provider_error`; el texto del proveedor (y su
/// `error_description`, que ni siquiera entra a `CallbackParams`) nunca se refleja: el
/// codigo sale siempre de una lista blanca fija.
#[tokio::test(start_paused = true)]
async fn error_desconocido_es_provider_error_y_no_se_refleja() {
    const LISTA_BLANCA: [&str; 8] = [
        "missing_pending",
        "invalid_state",
        "access_denied",
        "invalid_request",
        "provider_error",
        "exchange_failed",
        "provider_unavailable",
        "internal",
    ];
    let hostil = [
        "server_error",
        "<script>alert(1)</script>",
        "x\r\nSet-Cookie: a=b",
        "https://evil.example/phish",
        "",
    ];
    for error in hostil {
        let env = Env::new();
        let p = start(&env, None).await;
        let params = CallbackParams {
            code: None,
            state: Some(p.state.clone()),
            error: Some(error.to_owned()),
        };
        let e = env
            .app
            .complete_login(Some(&p.cookie), params, None)
            .await
            .unwrap_err();
        assert_eq!(e, LoginError::ProviderError, "error {error:?}");
        assert!(LISTA_BLANCA.contains(&e.code()));
        assert!(error.is_empty() || !e.code().contains(error));
        assert!(env.ports.sessions().is_empty());
    }
}

/// Login en curso caducado: pasados 600 s el callback es `InvalidState`, aunque el `code`
/// sea valido (un enlace de callback guardado no sirve horas despues). A 599 s aun vale.
#[tokio::test(start_paused = true)]
async fn pending_expirado_es_invalid_state() {
    let env = Env::new();
    let p = start(&env, None).await;
    let code = env.ports.idp().issue_code(&p.state, user());
    env.advance_secs(601).await;
    let r = env
        .app
        .complete_login(Some(&p.cookie), callback(&code, &p.state), None)
        .await;
    assert_eq!(r.unwrap_err(), LoginError::InvalidState);
    assert!(env.ports.sessions().is_empty());
    assert!(
        env.ports.pending().is_empty(),
        "el pending vencido tambien se consume"
    );
    assert_eq!(env.ports.idp().exchange_calls(), 0);

    let p = start(&env, None).await;
    let code = env.ports.idp().issue_code(&p.state, user());
    env.advance_secs(599).await;
    env.app
        .complete_login(Some(&p.cookie), callback(&code, &p.state), None)
        .await
        .unwrap();
}

/// El `ttl` guardado del login en curso es `created_at + 600 s`.
#[tokio::test(start_paused = true)]
async fn pending_guarda_ttl_de_10_minutos() {
    let env = Env::new();
    let p = start(&env, None).await;
    let hash = domain::PendingId::parse(&p.cookie).unwrap().hash();
    let now = env.ports.clock().now();
    assert_eq!(
        env.ports.pending().ttl_of(&hash),
        Some(now.saturating_add(secs(600)))
    );
}

/// Fijacion de sesion: el navegador llega al callback con una cookie de sesion previa
/// (p. ej. plantada por un atacante). Esa sesion se borra y la nueva tiene id distinto.
#[tokio::test(start_paused = true)]
async fn fijacion_de_sesion_borra_la_anterior_y_regenera_id() {
    let env = Env::new();
    let vieja = login(&env).await;

    let p = start(&env, None).await;
    let code = env.ports.idp().issue_code(&p.state, user());
    let done = env
        .app
        .complete_login(Some(&p.cookie), callback(&code, &p.state), Some(&vieja))
        .await
        .unwrap();
    let nueva = done.session_id.expose_secret();

    assert_ne!(nueva, vieja);
    assert!(env.ports.sessions().snapshot(&hash_of(&vieja)).is_none());
    assert!(env.ports.sessions().snapshot(&hash_of(&nueva)).is_some());
    assert_eq!(env.ports.sessions().len(), 1);
    assert_eq!(
        env.app.current_user(Some(&vieja)).await.unwrap_err(),
        AppError::Unauthorized
    );
}

/// Cada login emite un id de sesion nuevo aunque lo planten: una cookie con formato valido
/// pero inexistente no se adopta como id de la sesion.
#[tokio::test(start_paused = true)]
async fn cookie_plantada_inexistente_no_se_adopta() {
    let env = Env::new();
    let plantada = domain::SessionId::from_bytes([5; 32]).expose_secret();
    let p = start(&env, None).await;
    let code = env.ports.idp().issue_code(&p.state, user());
    let done = env
        .app
        .complete_login(Some(&p.cookie), callback(&code, &p.state), Some(&plantada))
        .await
        .unwrap();
    assert_ne!(done.session_id.expose_secret(), plantada);
}

/// Con sesion valida `start_login` no pasa por Cognito (y no deja un pending); con una
/// cookie invalida si.
#[tokio::test(start_paused = true)]
async fn start_login_con_sesion_valida_no_va_a_cognito() {
    let env = Env::new();
    let cookie = login(&env).await;
    let outcome = env.app.start_login(Some(&cookie), Some("/x")).await.unwrap();
    assert!(matches!(outcome, StartLoginOutcome::AlreadyAuthenticated(r) if r.as_str() == "/x"));
    assert!(env.ports.pending().is_empty());

    let outcome = env.app.start_login(Some("basura"), None).await.unwrap();
    assert!(matches!(outcome, StartLoginOutcome::Redirect { .. }));
    assert_eq!(env.ports.pending().len(), 1);
}

/// Open redirect: un `returnTo` hostil se reemplaza por la ruta por defecto.
#[tokio::test(start_paused = true)]
async fn return_to_externo_se_descarta() {
    let env = Env::new();
    for hostil in [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "javascript:alert(1)",
    ] {
        let p = start(&env, Some(hostil)).await;
        let code = env.ports.idp().issue_code(&p.state, user());
        let done = env
            .app
            .complete_login(Some(&p.cookie), callback(&code, &p.state), None)
            .await
            .unwrap();
        assert!(done.return_to.as_str().starts_with('/'), "{hostil}");
        assert!(!done.return_to.as_str().starts_with("//"), "{hostil}");
        assert!(!done.return_to.as_str().contains("evil"), "{hostil}");
    }
}
