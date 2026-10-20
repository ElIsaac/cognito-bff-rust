//! Flujo feliz del canje del code y mapeo de claims a `UserInfo`.

use std::time::Duration;

use application::ports::{IdentityProvider, IdpError};
use domain::{Email, GroupName};
use serde_json::json;

use crate::support::{
    ACCESS_TOKEN, CLIENT_SECRET, CODE, Env, Mock, REDIRECT_URI, REFRESH_TOKEN, key_a, verifier,
};

/// Flujo feliz: el canje devuelve access/refresh, la vigencia del access y un `UserInfo`
/// con `sub`, email verificado, nombre, grupos de `cognito:groups` y solo los claims de
/// `exposed_claims`.
#[tokio::test]
async fn canje_feliz_devuelve_tokens_y_userinfo() {
    let env = Env::start().await;
    let id = key_a().token(&env.claims());
    let grant = env.exchange(&id).await.unwrap();

    assert_eq!(grant.tokens.access.expose_secret(), ACCESS_TOKEN);
    assert_eq!(grant.tokens.refresh.expose_secret(), REFRESH_TOKEN);
    assert_eq!(grant.access_expires_in, Duration::from_secs(3600));
    let u = &grant.user;
    assert_eq!(u.sub().as_str(), "sub-0001-aaaa");
    assert_eq!(u.email().map(Email::as_str), Some("ana@example.com"));
    assert_eq!(u.name(), Some("Ana Perez"));
    let groups: Vec<_> = u.groups().iter().map(GroupName::as_str).collect();
    assert_eq!(groups, ["admins", "ventas"]);
    assert_eq!(u.attributes().len(), 1, "solo los claims de la lista blanca");
    assert_eq!(
        u.attributes().get("custom:tenant_id").map(String::as_str),
        Some("tenant-42")
    );
}

/// El form del canje lleva exactamente `grant_type=authorization_code`, `code`,
/// `redirect_uri` y `code_verifier` (PKCE), como `application/x-www-form-urlencoded`, y
/// el cliente se autentica con Basic `client_id:secret`. Nada mas viaja en el cuerpo (el
/// secreto no va en el form).
#[tokio::test]
async fn el_canje_envia_form_pkce_y_basic_auth_correctos() {
    let env = Env::start().await;
    let id = key_a().token(&env.claims());
    env.exchange(&id).await.unwrap();

    let reqs = env.mock.token_requests();
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    assert_eq!(
        r.authorization.as_deref(),
        Some(Mock::basic(CLIENT_SECRET).as_str())
    );
    assert_eq!(
        r.content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(r.field("grant_type"), Some("authorization_code"));
    assert_eq!(r.field("code"), Some(CODE));
    assert_eq!(r.field("redirect_uri"), Some(REDIRECT_URI));
    assert_eq!(r.field("code_verifier"), Some(verifier().expose_secret()));
    assert_eq!(r.form.len(), 4, "campos inesperados: {:?}", r.form);
    assert_eq!(env.secrets.gets(), 1);
    assert_eq!(env.secrets.invalidations(), 0);
}

/// Un atacante con un ID token valido pero cuyo `email_verified` es `false` (email
/// sin verificar, que podria suplantar a otro usuario aguas abajo) no obtiene email.
#[tokio::test]
async fn email_verified_false_no_expone_el_email() {
    let env = Env::start().await;
    let mut c = env.claims();
    c["email_verified"] = json!(false);
    let grant = env.exchange(&key_a().token(&c)).await.unwrap();
    assert!(grant.user.email().is_none());
    assert_eq!(
        grant.user.name(),
        Some("Ana Perez"),
        "el resto de claims se conserva"
    );
}

/// `email_verified` como la cadena `"false"` tampoco cuenta como verificado.
#[tokio::test]
async fn email_verified_cadena_false_no_expone_el_email() {
    let env = Env::start().await;
    let mut c = env.claims();
    c["email_verified"] = json!("false");
    let grant = env.exchange(&key_a().token(&c)).await.unwrap();
    assert!(grant.user.email().is_none());
}

/// Sin claim `email_verified` (o con un tipo raro como `1` o `"True"`) el email se
/// descarta: solo `true` o `"true"` exactos lo verifican.
#[tokio::test]
async fn email_verified_ausente_o_ambiguo_no_expone_el_email() {
    let env = Env::start().await;
    let mut c = env.claims();
    c.as_object_mut().unwrap().remove("email_verified");
    assert!(
        env.exchange(&key_a().token(&c))
            .await
            .unwrap()
            .user
            .email()
            .is_none()
    );
    for raro in [json!(1), json!("True"), json!("yes"), json!(null)] {
        c["email_verified"] = raro.clone();
        let grant = env.exchange(&key_a().token(&c)).await.unwrap();
        assert!(grant.user.email().is_none(), "{raro}");
    }
}

/// Cognito suele mandar `email_verified` como la cadena `"true"`: debe aceptarse.
#[tokio::test]
async fn email_verified_cadena_true_expone_el_email() {
    let env = Env::start().await;
    let mut c = env.claims();
    c["email_verified"] = json!("true");
    let grant = env.exchange(&key_a().token(&c)).await.unwrap();
    assert_eq!(grant.user.email().map(Email::as_str), Some("ana@example.com"));
}

/// Claims fuera de la lista blanca (`custom:otro`) o con valor no textual (objetos,
/// numeros) no llegan a `UserInfo::attributes`, aunque esten en el ID token.
#[tokio::test]
async fn solo_pasan_los_claims_expuestos_y_textuales() {
    let env =
        Env::start_with(|c| c.exposed_claims = vec!["custom:tenant_id".into(), "custom:num".into()]).await;
    let mut c = env.claims();
    c["custom:num"] = json!(5);
    let grant = env.exchange(&key_a().token(&c)).await.unwrap();
    let attrs = grant.user.attributes();
    assert_eq!(attrs.len(), 1);
    assert!(attrs.contains_key("custom:tenant_id"));
}

/// Un ID token sin `cognito:groups` y sin `name` (usuario sin grupos) es valido: grupos
/// vacios, nombre `None`.
#[tokio::test]
async fn usuario_sin_grupos_ni_nombre() {
    let env = Env::start().await;
    let mut c = env.claims();
    let o = c.as_object_mut().unwrap();
    o.remove("cognito:groups");
    o.remove("name");
    let grant = env.exchange(&key_a().token(&c)).await.unwrap();
    assert!(grant.user.groups().is_empty());
    assert_eq!(grant.user.name(), None);
}

/// Un `code` ya canjeado (o caducado) hace que Cognito responda `invalid_grant`: se
/// traduce a `InvalidGrant` (el callback repetido no obtiene sesion).
#[tokio::test]
async fn code_reutilizado_es_invalid_grant() {
    let env = Env::start().await;
    env.mock
        .push_token(crate::support::Reply::error(400, "invalid_grant"));
    let r = env.exchange_programmed().await;
    assert!(matches!(r, Err(IdpError::InvalidGrant)), "{r:?}");
}

/// El canje usa el endpoint del dominio configurado y el `Debug` del adaptador no revela
/// el secreto del cliente.
#[tokio::test]
async fn debug_del_adaptador_no_incluye_secretos() {
    let env = Env::start().await;
    let dbg = format!("{:?}", env.idp);
    assert!(!dbg.contains(CLIENT_SECRET), "{dbg}");
    assert!(env.idp.logout_url().starts_with(env.mock.base.as_str()));
}
