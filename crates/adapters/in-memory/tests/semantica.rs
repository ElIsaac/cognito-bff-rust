//! Semantica de los fakes: las condiciones que los adaptadores reales deben replicar.

#![allow(clippy::unwrap_used)]

use std::collections::HashSet;
use std::time::Duration;

use application::ports::{
    AdapterError, LeaseOutcome, PendingAuthStore, RandomGenerator, SessionRepository, UpdateOutcome,
};
use domain::{
    AccessToken, NewSession, PendingAuth, PendingId, RefreshToken, Session, SessionId, Subject, Timestamp,
    TokenSet, UserInfo, Version,
};
use in_memory::{MemPending, MemSessions, TestRng};

fn session(n: u8) -> Session {
    NewSession {
        id: SessionId::from_bytes([n; 32]),
        user: UserInfo::new(Subject::new("s".to_owned()).unwrap(), None, None, vec![]),
        tokens: TokenSet {
            access: AccessToken::new("a".to_owned()).unwrap(),
            refresh: RefreshToken::new("r".to_owned()).unwrap(),
        },
        access_expires_at: Timestamp::from_secs(100),
        absolute_expires_at: Timestamp::from_secs(1000),
        created_at: Timestamp::from_secs(0),
    }
    .into_session()
}

fn ts(s: u64) -> Timestamp {
    Timestamp::from_secs(s)
}

#[tokio::test]
async fn create_falla_si_ya_existe_y_guarda_el_ttl() {
    let repo = MemSessions::new();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();
    assert_eq!(repo.ttl_of(&s.id_hash), Some(ts(50)));
    assert_eq!(repo.create(&s, ts(60)).await, Err(AdapterError::Permanent));
    assert_eq!(repo.ttl_of(&s.id_hash), Some(ts(50)));
}

#[tokio::test]
async fn update_if_version_es_condicional() {
    let repo = MemSessions::new();
    let s = session(1);
    repo.create(&s, ts(50)).await.unwrap();
    let mut nueva = s.clone();
    nueva.version = s.version.next();
    assert_eq!(
        repo.update_if_version(&nueva, Version::from_stored(9), ts(70))
            .await,
        Ok(UpdateOutcome::Conflict)
    );
    assert_eq!(
        repo.update_if_version(&nueva, s.version, ts(70)).await,
        Ok(UpdateOutcome::Updated)
    );
    assert_eq!(repo.ttl_of(&s.id_hash), Some(ts(70)));
    assert_eq!(
        repo.update_if_version(&nueva, s.version, ts(80)).await,
        Ok(UpdateOutcome::Conflict),
        "la version ya avanzo"
    );
    let inexistente = session(2);
    assert_eq!(
        repo.update_if_version(&inexistente, inexistente.version, ts(1))
            .await,
        Ok(UpdateOutcome::Conflict)
    );
}

#[tokio::test]
async fn lease_exige_version_y_ausencia_o_vencimiento_estricto() {
    let repo = MemSessions::new();
    let s = session(1);
    let id = s.id_hash.clone();
    repo.create(&s, ts(500)).await.unwrap();

    assert_eq!(
        repo.acquire_refresh_lease(&id, Version::from_stored(7), ts(10), ts(20))
            .await,
        Ok(LeaseOutcome::Conflict),
        "version distinta"
    );
    assert_eq!(
        repo.acquire_refresh_lease(&id, s.version, ts(10), ts(20)).await,
        Ok(LeaseOutcome::Acquired {
            version: s.version.next()
        })
    );
    let guardada = repo.snapshot(&id).unwrap();
    assert_eq!(guardada.refresh_lock_until, Some(ts(20)));
    assert_eq!(guardada.version, s.version.next());

    let v = guardada.version;
    for now in [10, 19, 20] {
        assert_eq!(
            repo.acquire_refresh_lease(&id, v, ts(now), ts(now + 10)).await,
            Ok(LeaseOutcome::Conflict),
            "lease vigente o justo en el limite (now={now})"
        );
    }
    assert_eq!(
        repo.acquire_refresh_lease(&id, v, ts(21), ts(31)).await,
        Ok(LeaseOutcome::Acquired { version: v.next() })
    );
    assert_eq!(
        repo.acquire_refresh_lease(&session(9).id_hash, v, ts(21), ts(31))
            .await,
        Ok(LeaseOutcome::Conflict),
        "sesion inexistente"
    );
}

#[tokio::test]
async fn pending_se_consume_una_sola_vez() {
    let store = MemPending::new();
    let id = PendingId::from_bytes([3; 32]);
    let p = PendingAuth {
        id_hash: id.hash(),
        state: domain::State::from_bytes([1; 32]),
        nonce: domain::Nonce::from_bytes([2; 32]),
        code_verifier: domain::CodeVerifier::from_bytes([4; 32]),
        return_to: domain::ReturnTo::parse_or_default(None),
        created_at: ts(0),
    };
    store.put(&p, ts(600)).await.unwrap();
    assert_eq!(store.put(&p, ts(600)).await, Err(AdapterError::Permanent));
    assert!(store.consume(&id.hash()).await.unwrap().is_some());
    assert!(store.consume(&id.hash()).await.unwrap().is_none());
}

#[test]
fn el_rng_no_repite_y_below_respeta_el_rango() {
    let rng = TestRng::default();
    let vistos: HashSet<[u8; 32]> = (0..10_000).map(|_| rng.bytes32()).collect();
    assert_eq!(vistos.len(), 10_000);
    assert!((0..1000).all(|_| rng.below(7) < 7));
    assert_eq!(rng.below(1), 0);
}

#[tokio::test(start_paused = true)]
async fn el_reloj_avanza_con_el_tiempo_pausado() {
    use application::ports::Clock;
    let clock = in_memory::TestClock::new();
    let t0 = clock.now();
    assert_eq!(t0.as_secs(), in_memory::BASE_EPOCH_SECS);
    clock.advance(Duration::from_secs(90)).await;
    clock.sleep(Duration::from_secs(10)).await;
    assert_eq!(clock.now().saturating_since(t0), Duration::from_secs(100));
}
