//! Pruebas propias del adaptador contra `DynamoDB` Local: formato del item (plan, seccion 5),
//! items malformados y mapeo de errores. La bateria de contrato compartida con `in-memory`
//! vive en `crates/workspace-tests/tests/contrato`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use application::ports::{AdapterError, PendingAuthStore, SessionRepository, WsTicketStore};
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::retry::RetryConfig;
use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
};
use domain::{
    AccessToken, Email, GroupName, RefreshToken, Session, SessionId, Subject, Timestamp, TokenSet, UserInfo,
    Version,
};
use session_dynamodb::{DynamoPending, DynamoSessions, DynamoTickets};

static SEQ: AtomicU32 = AtomicU32::new(0);

fn client_for(endpoint: &str) -> Client {
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-2"))
        .endpoint_url(endpoint)
        .credentials_provider(Credentials::new("test", "test", None, None, "estatica"))
        .retry_config(RetryConfig::disabled())
        .build();
    Client::from_conf(config)
}

struct Tabla {
    client: Client,
    name: String,
}

impl Tabla {
    async fn nueva() -> Self {
        let endpoint = std::env::var("DYNAMODB_ENDPOINT_URL").expect("DYNAMODB_ENDPOINT_URL");
        let client = client_for(&endpoint);
        let name = format!(
            "formato-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        client
            .create_table()
            .table_name(&name)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("pk")
                    .attribute_type(ScalarAttributeType::S)
                    .build()
                    .unwrap(),
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("pk")
                    .key_type(KeyType::Hash)
                    .build()
                    .unwrap(),
            )
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await
            .unwrap();
        Self { client, name }
    }

    async fn raw(&self, pk: &str) -> Option<HashMap<String, AttributeValue>> {
        self.client
            .get_item()
            .table_name(&self.name)
            .key("pk", AttributeValue::S(pk.to_owned()))
            .consistent_read(true)
            .send()
            .await
            .unwrap()
            .item
    }

    async fn put_raw(&self, item: HashMap<String, AttributeValue>) {
        self.client
            .put_item()
            .table_name(&self.name)
            .set_item(Some(item))
            .send()
            .await
            .unwrap();
    }

    async fn borrar(self) {
        self.client
            .delete_table()
            .table_name(&self.name)
            .send()
            .await
            .unwrap();
    }
}

fn session() -> Session {
    let user = UserInfo::new(
        Subject::new("sub-1".to_owned()).unwrap(),
        Some(Email::new("a@b.com".to_owned()).unwrap()),
        Some("Ana".to_owned()),
        vec![GroupName::new("dueno".to_owned()).unwrap()],
    )
    .with_attributes([("custom:tenant_id".to_owned(), "t1".to_owned())]);
    Session {
        id_hash: SessionId::from_bytes([1; 32]).hash(),
        version: Version::INITIAL,
        user,
        tokens: TokenSet {
            access: AccessToken::new("acceso".to_owned()).unwrap(),
            refresh: RefreshToken::new("refresco".to_owned()).unwrap(),
        },
        access_expires_at: Timestamp::from_secs(100),
        absolute_expires_at: Timestamp::from_secs(1000),
        last_seen_at: Timestamp::from_secs(10),
        refresh_lock_until: None,
        created_at: Timestamp::from_secs(1),
    }
}

fn s(v: &str) -> AttributeValue {
    AttributeValue::S(v.to_owned())
}

fn n(v: u64) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

#[tokio::test]
async fn formato_del_item_de_sesion() {
    let tabla = Tabla::nueva().await;
    let repo = DynamoSessions::new(tabla.client.clone(), &tabla.name);
    let sesion = session();
    repo.create(&sesion, Timestamp::from_secs(500)).await.unwrap();

    let pk = format!("SESSION#{}", sesion.id_hash.as_str());
    let item = tabla.raw(&pk).await.expect("item");
    assert_eq!(item.get("pk"), Some(&s(&pk)));
    assert_eq!(item.get("version"), Some(&n(1)));
    assert_eq!(item.get("access_token"), Some(&s("acceso")));
    assert_eq!(item.get("refresh_token"), Some(&s("refresco")));
    assert_eq!(item.get("access_expires_at"), Some(&n(100)));
    assert_eq!(item.get("absolute_expires_at"), Some(&n(1000)));
    assert_eq!(item.get("last_seen_at"), Some(&n(10)));
    assert_eq!(item.get("created_at"), Some(&n(1)));
    assert_eq!(item.get("ttl"), Some(&n(500)));
    assert!(!item.contains_key("refresh_lock_until"));
    let Some(AttributeValue::M(user)) = item.get("user") else {
        panic!("user debe ser M");
    };
    assert_eq!(user.get("sub"), Some(&s("sub-1")));
    assert_eq!(user.get("email"), Some(&s("a@b.com")));
    assert_eq!(user.get("name"), Some(&s("Ana")));
    assert_eq!(user.get("groups"), Some(&AttributeValue::L(vec![s("dueno")])));
    assert_eq!(
        user.get("attributes"),
        Some(&AttributeValue::M(HashMap::from([(
            "custom:tenant_id".to_owned(),
            s("t1")
        )])))
    );
    tabla.borrar().await;
}

#[tokio::test]
async fn acepta_grupos_como_string_set() {
    let tabla = Tabla::nueva().await;
    let repo = DynamoSessions::new(tabla.client.clone(), &tabla.name);
    let sesion = session();
    let pk = format!("SESSION#{}", sesion.id_hash.as_str());
    tabla
        .put_raw(HashMap::from([
            ("pk".to_owned(), s(&pk)),
            ("version".to_owned(), n(4)),
            (
                "user".to_owned(),
                AttributeValue::M(HashMap::from([
                    ("sub".to_owned(), s("sub-1")),
                    ("groups".to_owned(), AttributeValue::Ss(vec!["dueno".to_owned()])),
                ])),
            ),
            ("access_token".to_owned(), s("a")),
            ("refresh_token".to_owned(), s("r")),
            ("access_expires_at".to_owned(), n(1)),
            ("absolute_expires_at".to_owned(), n(2)),
            ("last_seen_at".to_owned(), n(3)),
            ("created_at".to_owned(), n(4)),
            ("ttl".to_owned(), n(5)),
        ]))
        .await;
    let leida = repo.get(&sesion.id_hash).await.unwrap().unwrap();
    assert_eq!(leida.user.groups().len(), 1);
    assert_eq!(leida.version, Version::from_stored(4));
    tabla.borrar().await;
}

#[tokio::test]
async fn items_malformados_son_permanentes() {
    let tabla = Tabla::nueva().await;
    let sessions = DynamoSessions::new(tabla.client.clone(), &tabla.name);
    let pending = DynamoPending::new(tabla.client.clone(), &tabla.name);
    let tickets = DynamoTickets::new(tabla.client.clone(), &tabla.name);
    let sesion = session();

    // Sin atributos, version no numerica y usuario de tipo equivocado.
    tabla
        .put_raw(HashMap::from([(
            "pk".to_owned(),
            s(&format!("SESSION#{}", sesion.id_hash.as_str())),
        )]))
        .await;
    assert_eq!(
        sessions.get(&sesion.id_hash).await.err(),
        Some(AdapterError::Permanent)
    );

    let malo = domain::IdHash::from_stored("otro".to_owned());
    tabla
        .put_raw(HashMap::from([
            ("pk".to_owned(), s("SESSION#otro")),
            ("version".to_owned(), s("uno")),
        ]))
        .await;
    assert_eq!(sessions.get(&malo).await.err(), Some(AdapterError::Permanent));

    tabla
        .put_raw(HashMap::from([("pk".to_owned(), s("PENDING#x"))]))
        .await;
    assert_eq!(
        pending
            .consume(&domain::IdHash::from_stored("x".to_owned()))
            .await
            .err(),
        Some(AdapterError::Permanent)
    );
    tabla
        .put_raw(HashMap::from([("pk".to_owned(), s("WSTICKET#x"))]))
        .await;
    assert_eq!(
        tickets
            .consume(&domain::IdHash::from_stored("x".to_owned()))
            .await
            .err(),
        Some(AdapterError::Permanent)
    );
    tabla.borrar().await;
}

#[tokio::test]
async fn endpoint_caido_es_transitorio() {
    // Puerto 1: conexion rechazada.
    let repo = DynamoSessions::new(client_for("http://127.0.0.1:1"), "no-importa");
    assert_eq!(
        repo.get(&session().id_hash).await.err(),
        Some(AdapterError::Transient)
    );
    assert_eq!(
        repo.create(&session(), Timestamp::from_secs(1)).await,
        Err(AdapterError::Transient)
    );
}

#[tokio::test]
async fn tabla_inexistente_es_permanente() {
    let endpoint = std::env::var("DYNAMODB_ENDPOINT_URL").expect("DYNAMODB_ENDPOINT_URL");
    let repo = DynamoSessions::new(client_for(&endpoint), "tabla-que-no-existe");
    assert_eq!(
        repo.get(&session().id_hash).await.err(),
        Some(AdapterError::Permanent)
    );
}
