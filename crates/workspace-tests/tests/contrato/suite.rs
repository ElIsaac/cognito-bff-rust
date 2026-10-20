//! Bateria de contrato, generica sobre las implementaciones de los puertos de almacenamiento.

#![allow(clippy::unwrap_used, clippy::similar_names, clippy::many_single_char_names)]

use std::sync::Arc;

use application::ports::{
    AdapterError, LeaseOutcome, PendingAuthStore, SessionRepository, UpdateOutcome, WsTicketStore,
};
use domain::{
    AccessToken, CodeVerifier, Email, GroupName, IdHash, Nonce, PendingAuth, PendingId, RefreshToken,
    ReturnTo, Session, SessionId, State, Subject, Timestamp, TokenSet, UserInfo, Version, WsTicket,
    WsTicketId,
};
use tokio::task::JoinSet;

/// Lo que la bateria necesita de cada implementacion: los tres almacenes y sondas para ver
/// lo que realmente quedo guardado (ttl y presencia del atributo del lease).
pub trait Harness: Send + Sync + 'static {
    type Sessions: SessionRepository + 'static;
    type Pending: PendingAuthStore + 'static;
    type Tickets: WsTicketStore + 'static;

    fn sessions(&self) -> Arc<Self::Sessions>;
    fn pending(&self) -> Arc<Self::Pending>;
    fn tickets(&self) -> Arc<Self::Tickets>;

    async fn session_ttl(&self, id: &IdHash) -> Option<Timestamp>;
    async fn session_has_lock_attr(&self, id: &IdHash) -> bool;
    async fn pending_ttl(&self, id: &IdHash) -> Option<Timestamp>;
    async fn ticket_ttl(&self, id: &IdHash) -> Option<Timestamp>;
}

fn ts(s: u64) -> Timestamp {
    Timestamp::from_secs(s)
}

fn minimal_user() -> UserInfo {
    UserInfo::new(Subject::new("sub-minimo".to_owned()).unwrap(), None, None, vec![])
}

fn full_user() -> UserInfo {
    UserInfo::new(
        Subject::new("1b2c-3d4e".to_owned()).unwrap(),
        Some(Email::new("ana@example.com".to_owned()).unwrap()),
        Some("Ana Pérez Núñez".to_owned()),
        vec![
            GroupName::new("dueno".to_owned()).unwrap(),
            GroupName::new("ventas".to_owned()).unwrap(),
        ],
    )
    .with_attributes([
        ("custom:tenant_id".to_owned(), "t-42".to_owned()),
        ("custom:region".to_owned(), "mx".to_owned()),
    ])
}

fn session_with(n: u8, user: UserInfo) -> Session {
    Session {
        id_hash: SessionId::from_bytes([n; 32]).hash(),
        version: Version::INITIAL,
        user,
        tokens: TokenSet {
            access: AccessToken::new(format!("acceso.{n}.abc")).unwrap(),
            refresh: RefreshToken::new(format!("refresco.{n}.xyz")).unwrap(),
        },
        access_expires_at: ts(100),
        absolute_expires_at: ts(1000),
        last_seen_at: ts(10),
        refresh_lock_until: None,
        created_at: ts(1),
    }
}

fn session(n: u8) -> Session {
    session_with(n, minimal_user())
}

fn assert_same_user(a: &UserInfo, b: &UserInfo) {
    assert_eq!(a, b);
    assert_eq!(a.attributes(), b.attributes());
    let g = |u: &UserInfo| {
        u.groups()
            .iter()
            .map(|g| g.as_str().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(g(a), g(b));
}

fn assert_same(a: &Session, b: &Session) {
    assert_eq!(a.id_hash, b.id_hash);
    assert_eq!(a.version, b.version);
    assert_same_user(&a.user, &b.user);
    assert_eq!(a.tokens.access.expose_secret(), b.tokens.access.expose_secret());
    assert_eq!(a.tokens.refresh.expose_secret(), b.tokens.refresh.expose_secret());
    assert_eq!(a.access_expires_at, b.access_expires_at);
    assert_eq!(a.absolute_expires_at, b.absolute_expires_at);
    assert_eq!(a.last_seen_at, b.last_seen_at);
    assert_eq!(a.refresh_lock_until, b.refresh_lock_until);
    assert_eq!(a.created_at, b.created_at);
}

fn pending(n: u8) -> PendingAuth {
    PendingAuth {
        id_hash: PendingId::from_bytes([n; 32]).hash(),
        state: State::from_bytes([n.wrapping_add(1); 32]),
        nonce: Nonce::from_bytes([n.wrapping_add(2); 32]),
        code_verifier: CodeVerifier::from_bytes([n.wrapping_add(3); 32]),
        return_to: ReturnTo::parse("/panel/ventas?mes=10&q=a%20b").unwrap(),
        created_at: ts(5),
    }
}

fn ticket(n: u8, user: UserInfo) -> WsTicket {
    WsTicket {
        id_hash: WsTicketId::from_bytes([n; 32]).hash(),
        session_hash: SessionId::from_bytes([n.wrapping_add(1); 32]).hash(),
        user,
        created_at: ts(7),
    }
}

// ---------------------------------------------------------------------------------------
// Sesiones
// ---------------------------------------------------------------------------------------

pub async fn get_de_inexistente_es_none<H: Harness>(h: &H) {
    assert!(h.sessions().get(&session(1).id_hash).await.unwrap().is_none());
}

pub async fn create_duplicado_es_permanente_y_no_pisa<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();
    let mut otra = s.clone();
    otra.last_seen_at = ts(999);
    assert_eq!(repo.create(&otra, ts(60)).await, Err(AdapterError::Permanent));
    let guardada = repo.get(&s.id_hash).await.unwrap().unwrap();
    assert_same(&guardada, &s);
    assert_eq!(h.session_ttl(&s.id_hash).await, Some(ts(50)));
}

pub async fn roundtrip_completo_de_sesion<H: Harness>(h: &H) {
    let repo = h.sessions();
    let mut s = session_with(2, full_user());
    s.refresh_lock_until = Some(ts(77));
    repo.create(&s, ts(500)).await.unwrap();
    let leida = repo.get(&s.id_hash).await.unwrap().unwrap();
    assert_same(&leida, &s);
    assert_eq!(leida.user.attributes().len(), 2);
    assert_eq!(leida.user.name(), Some("Ana Pérez Núñez"));
}

pub async fn roundtrip_con_usuario_minimo<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(3);
    repo.create(&s, ts(500)).await.unwrap();
    let leida = repo.get(&s.id_hash).await.unwrap().unwrap();
    assert_same(&leida, &s);
    assert!(leida.user.groups().is_empty());
    assert!(leida.user.attributes().is_empty());
    assert!(leida.user.email().is_none());
    assert!(leida.user.name().is_none());
    assert!(leida.refresh_lock_until.is_none());

    let t = ticket(3, minimal_user());
    h.tickets().put(&t, ts(60)).await.unwrap();
    let leido = h.tickets().consume(&t.id_hash).await.unwrap().unwrap();
    assert_same_user(&leido.user, &t.user);
}

pub async fn update_con_version_correcta<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();
    let mut nueva = session_with(1, full_user());
    nueva.version = s.version.next();
    nueva.tokens.access = AccessToken::new("acceso.nuevo".to_owned()).unwrap();
    assert_eq!(
        repo.update_if_version(&nueva, s.version, ts(70)).await,
        Ok(UpdateOutcome::Updated)
    );
    let leida = repo.get(&s.id_hash).await.unwrap().unwrap();
    assert_same(&leida, &nueva);
}

pub async fn update_con_version_incorrecta_es_conflicto<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();
    let mut nueva = s.clone();
    nueva.version = Version::from_stored(10);
    nueva.last_seen_at = ts(999);
    assert_eq!(
        repo.update_if_version(&nueva, Version::from_stored(9), ts(70))
            .await,
        Ok(UpdateOutcome::Conflict)
    );
    let leida = repo.get(&s.id_hash).await.unwrap().unwrap();
    assert_same(&leida, &s);
    assert_eq!(h.session_ttl(&s.id_hash).await, Some(ts(50)));
}

pub async fn update_de_inexistente_es_conflicto<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    assert_eq!(
        repo.update_if_version(&s, s.version, ts(70)).await,
        Ok(UpdateOutcome::Conflict)
    );
    assert!(repo.get(&s.id_hash).await.unwrap().is_none());
}

pub async fn update_borra_refresh_lock_until<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();
    let LeaseOutcome::Acquired { version } = repo
        .acquire_refresh_lease(&s.id_hash, s.version, ts(10), ts(20))
        .await
        .unwrap()
    else {
        panic!("el lease debio tomarse");
    };
    assert!(h.session_has_lock_attr(&s.id_hash).await);
    let mut liberada = s.clone();
    liberada.version = version.next();
    liberada.refresh_lock_until = None;
    assert_eq!(
        repo.update_if_version(&liberada, version, ts(60)).await,
        Ok(UpdateOutcome::Updated)
    );
    assert!(!h.session_has_lock_attr(&s.id_hash).await);
    let leida = repo.get(&s.id_hash).await.unwrap().unwrap();
    assert!(leida.refresh_lock_until.is_none());
    assert_eq!(leida.version, Version::from_stored(3));
}

pub async fn ttl_de_sesion_persistido_y_actualizado<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();
    assert_eq!(h.session_ttl(&s.id_hash).await, Some(ts(50)));
    let mut nueva = s.clone();
    nueva.version = s.version.next();
    repo.update_if_version(&nueva, s.version, ts(70)).await.unwrap();
    assert_eq!(h.session_ttl(&s.id_hash).await, Some(ts(70)));
}

// ---------------------------------------------------------------------------------------
// Lease
// ---------------------------------------------------------------------------------------

pub async fn lease_libre<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();
    assert_eq!(
        repo.acquire_refresh_lease(&s.id_hash, s.version, ts(100), ts(110))
            .await,
        Ok(LeaseOutcome::Acquired {
            version: Version::from_stored(2)
        })
    );
    let leida = repo.get(&s.id_hash).await.unwrap().unwrap();
    assert_eq!(leida.version, Version::from_stored(2));
    assert_eq!(leida.refresh_lock_until, Some(ts(110)));
    assert_eq!(h.session_ttl(&s.id_hash).await, Some(ts(50)));
    assert_eq!(
        leida.tokens.refresh.expose_secret(),
        s.tokens.refresh.expose_secret()
    );
}

pub async fn lease_vigente_es_conflicto<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();
    repo.acquire_refresh_lease(&s.id_hash, s.version, ts(100), ts(110))
        .await
        .unwrap();
    // Con la version nueva y el lease vigente.
    assert_eq!(
        repo.acquire_refresh_lease(&s.id_hash, Version::from_stored(2), ts(105), ts(115))
            .await,
        Ok(LeaseOutcome::Conflict)
    );
    // Con la version vieja.
    assert_eq!(
        repo.acquire_refresh_lease(&s.id_hash, s.version, ts(105), ts(115))
            .await,
        Ok(LeaseOutcome::Conflict)
    );
    let leida = repo.get(&s.id_hash).await.unwrap().unwrap();
    assert_eq!(leida.version, Version::from_stored(2));
    assert_eq!(leida.refresh_lock_until, Some(ts(110)));
}

pub async fn lease_vencido_se_toma<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();
    repo.acquire_refresh_lease(&s.id_hash, s.version, ts(100), ts(110))
        .await
        .unwrap();
    assert_eq!(
        repo.acquire_refresh_lease(&s.id_hash, Version::from_stored(2), ts(111), ts(121))
            .await,
        Ok(LeaseOutcome::Acquired {
            version: Version::from_stored(3)
        })
    );
    let leida = repo.get(&s.id_hash).await.unwrap().unwrap();
    assert_eq!(leida.version, Version::from_stored(3));
    assert_eq!(leida.refresh_lock_until, Some(ts(121)));
}

pub async fn lease_en_el_limite_exacto_es_conflicto<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();
    repo.acquire_refresh_lease(&s.id_hash, s.version, ts(100), ts(110))
        .await
        .unwrap();
    // lock == now: sigue vigente (la condicion es `lock < now`).
    assert_eq!(
        repo.acquire_refresh_lease(&s.id_hash, Version::from_stored(2), ts(110), ts(120))
            .await,
        Ok(LeaseOutcome::Conflict)
    );
    assert_eq!(
        repo.acquire_refresh_lease(&s.id_hash, Version::from_stored(2), ts(111), ts(120))
            .await,
        Ok(LeaseOutcome::Acquired {
            version: Version::from_stored(3)
        })
    );
}

pub async fn lease_con_version_distinta_es_conflicto<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();
    assert_eq!(
        repo.acquire_refresh_lease(&s.id_hash, Version::from_stored(9), ts(100), ts(110))
            .await,
        Ok(LeaseOutcome::Conflict)
    );
    let leida = repo.get(&s.id_hash).await.unwrap().unwrap();
    assert_eq!(leida.version, s.version);
    assert!(leida.refresh_lock_until.is_none());
    assert!(!h.session_has_lock_attr(&s.id_hash).await);
}

pub async fn lease_de_inexistente_es_conflicto<H: Harness>(h: &H) {
    let repo = h.sessions();
    assert_eq!(
        repo.acquire_refresh_lease(&session(1).id_hash, Version::INITIAL, ts(100), ts(110))
            .await,
        Ok(LeaseOutcome::Conflict)
    );
}

pub async fn lease_no_crea_la_sesion<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    repo.acquire_refresh_lease(&s.id_hash, s.version, ts(100), ts(110))
        .await
        .unwrap();
    assert!(repo.get(&s.id_hash).await.unwrap().is_none());
    assert!(h.session_ttl(&s.id_hash).await.is_none());
}

pub async fn delete_es_idempotente<H: Harness>(h: &H) {
    let repo = h.sessions();
    let s = session(1);
    assert_eq!(repo.delete(&s.id_hash).await, Ok(()));
    repo.create(&s, ts(50)).await.unwrap();
    assert_eq!(repo.delete(&s.id_hash).await, Ok(()));
    assert!(repo.get(&s.id_hash).await.unwrap().is_none());
    assert_eq!(repo.delete(&s.id_hash).await, Ok(()));
    // Tras borrar se puede volver a crear.
    repo.create(&s, ts(50)).await.unwrap();
}

pub async fn carrera_de_50_leases_un_solo_ganador<H: Harness>(h: &H) {
    const TAREAS: usize = 50;
    let repo = h.sessions();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();

    let mut tareas = JoinSet::new();
    for _ in 0..TAREAS {
        let repo = Arc::clone(&repo);
        let (id, v) = (s.id_hash.clone(), s.version);
        tareas.spawn(async move { repo.acquire_refresh_lease(&id, v, ts(100), ts(110)).await });
    }
    let (mut ganadores, mut conflictos) = (0, 0);
    while let Some(r) = tareas.join_next().await {
        match r.unwrap().unwrap() {
            LeaseOutcome::Acquired { version } => {
                assert_eq!(version, Version::from_stored(2));
                ganadores += 1;
            }
            LeaseOutcome::Conflict => conflictos += 1,
        }
    }
    assert_eq!(ganadores, 1);
    assert_eq!(conflictos, TAREAS - 1);
    let leida = repo.get(&s.id_hash).await.unwrap().unwrap();
    assert_eq!(leida.version, Version::from_stored(2));
}

// ---------------------------------------------------------------------------------------
// Login en curso y boleto
// ---------------------------------------------------------------------------------------

pub async fn pending_roundtrip_y_ttl<H: Harness>(h: &H) {
    let p = pending(1);
    h.pending().put(&p, ts(605)).await.unwrap();
    assert_eq!(h.pending_ttl(&p.id_hash).await, Some(ts(605)));
    let leida = h.pending().consume(&p.id_hash).await.unwrap().unwrap();
    assert_eq!(leida.id_hash, p.id_hash);
    assert_eq!(leida.state.expose_secret(), p.state.expose_secret());
    assert_eq!(leida.nonce.expose_secret(), p.nonce.expose_secret());
    assert_eq!(
        leida.code_verifier.expose_secret(),
        p.code_verifier.expose_secret()
    );
    assert_eq!(leida.return_to, p.return_to);
    assert_eq!(leida.created_at, p.created_at);
}

pub async fn pending_se_consume_una_sola_vez<H: Harness>(h: &H) {
    let p = pending(1);
    assert!(h.pending().consume(&p.id_hash).await.unwrap().is_none());
    h.pending().put(&p, ts(605)).await.unwrap();
    assert!(h.pending().consume(&p.id_hash).await.unwrap().is_some());
    assert!(h.pending().consume(&p.id_hash).await.unwrap().is_none());
    assert!(h.pending_ttl(&p.id_hash).await.is_none());
}

pub async fn pending_duplicado_es_permanente<H: Harness>(h: &H) {
    let p = pending(1);
    h.pending().put(&p, ts(605)).await.unwrap();
    let mut otro = pending(1);
    otro.created_at = ts(9999);
    assert_eq!(
        h.pending().put(&otro, ts(700)).await,
        Err(AdapterError::Permanent)
    );
    let leida = h.pending().consume(&p.id_hash).await.unwrap().unwrap();
    assert_eq!(leida.created_at, p.created_at);
}

pub async fn ticket_roundtrip_y_ttl<H: Harness>(h: &H) {
    let t = ticket(1, full_user());
    h.tickets().put(&t, ts(37)).await.unwrap();
    assert_eq!(h.ticket_ttl(&t.id_hash).await, Some(ts(37)));
    let leido = h.tickets().consume(&t.id_hash).await.unwrap().unwrap();
    assert_eq!(leido.id_hash, t.id_hash);
    assert_eq!(leido.session_hash, t.session_hash);
    assert_same_user(&leido.user, &t.user);
    assert_eq!(leido.created_at, t.created_at);
}

pub async fn ticket_se_consume_una_sola_vez<H: Harness>(h: &H) {
    let t = ticket(1, minimal_user());
    assert!(h.tickets().consume(&t.id_hash).await.unwrap().is_none());
    h.tickets().put(&t, ts(37)).await.unwrap();
    assert_eq!(h.tickets().put(&t, ts(40)).await, Err(AdapterError::Permanent));
    assert!(h.tickets().consume(&t.id_hash).await.unwrap().is_some());
    assert!(h.tickets().consume(&t.id_hash).await.unwrap().is_none());
}

pub async fn consume_concurrente_devuelve_una_sola_vez<H: Harness>(h: &H) {
    let (p, t) = (pending(1), ticket(1, minimal_user()));
    h.pending().put(&p, ts(605)).await.unwrap();
    h.tickets().put(&t, ts(37)).await.unwrap();
    let mut tareas = JoinSet::new();
    for _ in 0..20 {
        let (pend, tick) = (h.pending(), h.tickets());
        let (pid, tid) = (p.id_hash.clone(), t.id_hash.clone());
        tareas.spawn(async move {
            let a = pend.consume(&pid).await.unwrap().is_some();
            let b = tick.consume(&tid).await.unwrap().is_some();
            (a, b)
        });
    }
    let (mut pendings, mut tickets) = (0, 0);
    while let Some(r) = tareas.join_next().await {
        let (a, b) = r.unwrap();
        pendings += usize::from(a);
        tickets += usize::from(b);
    }
    assert_eq!((pendings, tickets), (1, 1));
}

/// Con el mismo hash, sesion, login en curso y boleto no se pisan entre si (en `DynamoDB`
/// comparten tabla y los separa el prefijo de `pk`).
pub async fn namespaces_separados_por_prefijo<H: Harness>(h: &H) {
    let mismo = IdHash::from_stored("mismo-hash".to_owned());
    let mut s = session(1);
    s.id_hash = mismo.clone();
    let mut p = pending(1);
    p.id_hash = mismo.clone();
    let mut t = ticket(1, minimal_user());
    t.id_hash = mismo.clone();

    h.sessions().create(&s, ts(50)).await.unwrap();
    h.pending().put(&p, ts(60)).await.unwrap();
    h.tickets().put(&t, ts(70)).await.unwrap();

    assert!(h.pending().consume(&mismo).await.unwrap().is_some());
    assert!(h.sessions().get(&mismo).await.unwrap().is_some());
    assert!(h.tickets().consume(&mismo).await.unwrap().is_some());
    assert!(h.sessions().get(&mismo).await.unwrap().is_some());
}
