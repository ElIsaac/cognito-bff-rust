//! Fugas de informacion: nada secreto sale por `tracing` ni por `Debug`.

use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use application::ports::{AdapterError, IdentityProvider};
use domain::RefreshToken;
use serde_json::json;
use tracing::field::{Field, Visit};
use tracing::{Event, Metadata, Subscriber, span};

use crate::support::{
    ACCESS_TOKEN, CLIENT_SECRET, CODE, Env, Mock, NEW_REFRESH_TOKEN, REFRESH_TOKEN, Reply, key_a,
    key_attacker, nonce, other_nonce, verifier,
};

/// Subscriber minimo que guarda cada evento y cada span (con todos sus campos, en formato
/// `Debug`) como una linea de texto.
#[derive(Clone, Default)]
struct Captura {
    lineas: Arc<Mutex<Vec<String>>>,
    siguiente: Arc<AtomicU64>,
}

struct Campos<'a>(&'a mut String);

impl Visit for Campos<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

impl Captura {
    fn push(&self, linea: String) {
        self.lineas.lock().unwrap().push(linea);
    }

    fn todo(&self) -> Vec<String> {
        self.lineas.lock().unwrap().clone()
    }
}

impl Subscriber for Captura {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attrs: &span::Attributes<'_>) -> span::Id {
        let mut s = format!("SPAN {} {}", attrs.metadata().target(), attrs.metadata().name());
        attrs.record(&mut Campos(&mut s));
        self.push(s);
        span::Id::from_u64(self.siguiente.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _: &span::Id, values: &span::Record<'_>) {
        let mut s = String::from("SPAN-RECORD");
        values.record(&mut Campos(&mut s));
        self.push(s);
    }

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let m = event.metadata();
        let mut s = format!("{} {} {}", m.level(), m.target(), m.name());
        event.record(&mut Campos(&mut s));
        self.push(s);
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

/// Todos los flujos del adaptador (exitosos, rechazados y con error) bajo captura: ningun
/// log contiene el ID token, el access token, el refresh token (ni el rotado), el `code`,
/// el `code_verifier`, el client secret (ni en Basic base64), ni el nonce (propio o ajeno).
/// Ademas `Debug` del adaptador no los revela. Se exige que la captura no este vacia: un
/// subscriber roto no prueba nada.
#[tokio::test]
async fn ningun_log_contiene_secretos() {
    let captura = Captura::default();
    // Con un unico `Dispatch` registrado en el proceso, `tracing` calcula el interes de cada
    // callsite solo contra el subscriber del hilo que lo registra: otro test en paralelo
    // podria dejarlo desactivado. Un segundo `Dispatch` fuerza el calculo contra todos.
    let _otro = tracing::Dispatch::new(Captura::default());
    let dispatch = tracing::Dispatch::new(captura.clone());
    let guard = tracing::dispatcher::set_default(&dispatch);

    let env = Env::start().await;
    let mut secretos: Vec<(&str, String)> = vec![
        ("access token", ACCESS_TOKEN.into()),
        ("refresh token", REFRESH_TOKEN.into()),
        ("refresh rotado", NEW_REFRESH_TOKEN.into()),
        ("code", CODE.into()),
        ("code_verifier", verifier().expose_secret().into()),
        ("client secret", CLIENT_SECRET.into()),
        ("client secret en Basic", Mock::basic(CLIENT_SECRET)),
        ("nonce", nonce().expose_secret()),
        ("nonce ajeno", other_nonce().expose_secret()),
    ];
    let refresh = RefreshToken::new(REFRESH_TOKEN.into()).unwrap();

    // Canje exitoso.
    let bueno = key_a().token(&env.claims());
    secretos.push(("id_token valido", bueno.clone()));
    env.exchange(&bueno).await.unwrap();

    // ID tokens rechazados (firma, nonce, aud, expirado, malformado).
    let mut c = env.claims();
    let forjado = key_attacker().token(&c);
    c["nonce"] = json!(other_nonce().expose_secret());
    let nonce_malo = key_a().token(&c);
    let mut c = env.claims();
    c["aud"] = json!("otro");
    let aud_malo = key_a().token(&c);
    let mut c = env.claims();
    c["exp"] = json!(1);
    let vencido = key_a().token(&c);
    for (n, t) in [
        ("id_token forjado", forjado),
        ("id_token nonce malo", nonce_malo),
        ("id_token aud malo", aud_malo),
        ("id_token vencido", vencido),
    ] {
        secretos.push((n, t.clone()));
        env.assert_rejected(&t).await;
    }
    env.assert_rejected("basura.que.no-es-jwt").await;

    // Errores del token endpoint.
    env.mock.push_token(Reply::error(400, "invalid_grant"));
    env.exchange_programmed().await.unwrap_err();
    env.mock.push_token(Reply::raw(503, "upstream roto"));
    env.exchange_programmed().await.unwrap_err();
    env.mock.push_token(Reply::raw(200, "no es json"));
    env.exchange_programmed().await.unwrap_err();
    env.mock.push_token(Reply::tokens(None, Some(REFRESH_TOKEN)));
    env.exchange_programmed().await.unwrap_err();

    // Rotacion de secreto e invalid_client persistente.
    env.mock.set_expected_secret(Some("otro-secreto-rotado-0003"));
    env.secrets.rotate_on_invalidate("otro-secreto-rotado-0003");
    secretos.push(("secreto rotado", "otro-secreto-rotado-0003".into()));
    secretos.push(("secreto rotado en Basic", Mock::basic("otro-secreto-rotado-0003")));
    env.mock
        .push_token(Reply::tokens(Some(&bueno), Some(REFRESH_TOKEN)));
    env.exchange_programmed().await.unwrap();
    env.secrets.set_current("secreto-equivocado-0004");
    secretos.push(("secreto equivocado", "secreto-equivocado-0004".into())); // gitleaks:allow (valor de prueba)
    env.exchange_programmed().await.unwrap_err();
    env.secrets.set_current("otro-secreto-rotado-0003");
    env.secrets.fail_with(AdapterError::Transient);
    env.exchange_programmed().await.unwrap_err();

    // Refresh y revoke.
    let env2 = Env::start().await;
    let mut c = env2.claims();
    c.as_object_mut().unwrap().remove("nonce");
    let id_refresh = key_a().token(&c);
    secretos.push(("id_token de refresh", id_refresh.clone()));
    env2.mock
        .push_token(Reply::tokens(Some(&id_refresh), Some(NEW_REFRESH_TOKEN)));
    env2.idp.refresh(&refresh).await.unwrap();
    env2.mock.push_token(Reply::error(400, "invalid_grant"));
    env2.idp.refresh(&refresh).await.unwrap_err();
    env2.mock.push_revoke(Reply::raw(200, ""));
    env2.idp.revoke(&refresh).await.unwrap();
    env2.mock.push_revoke(Reply::raw(503, ""));
    env2.idp.revoke(&refresh).await.unwrap_err();

    let debug_idp = format!("{:?} {:?}", env.idp, env2.idp);
    drop(guard);

    let lineas = captura.todo();
    assert!(
        lineas.len() > 15,
        "la captura casi no vio eventos: {}",
        lineas.len()
    );
    for (nombre, valor) in &secretos {
        assert!(valor.len() >= 16, "{nombre} demasiado corto para buscarlo");
        assert!(
            !debug_idp.contains(valor.as_str()),
            "Debug del adaptador filtra {nombre}"
        );
        for linea in &lineas {
            assert!(
                !linea.contains(valor.as_str()),
                "{nombre} aparece en el log: {linea}"
            );
        }
    }
}

/// `Debug` del adaptador: no incluye secretos del cliente ni material de llaves.
#[tokio::test]
async fn debug_del_adaptador_no_filtra() {
    let env = Env::start().await;
    let dbg = format!("{:?}", env.idp);
    for s in [CLIENT_SECRET, key_a().n.as_str(), key_a().e.as_str()] {
        assert!(!dbg.contains(s), "{dbg}");
    }
}
