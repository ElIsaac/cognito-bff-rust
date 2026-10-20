#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
    TimeToLiveSpecification,
};
use domain::{IdHash, Timestamp};
use session_dynamodb::{DynamoPending, DynamoSessions, DynamoTickets};

static SEQ: AtomicU32 = AtomicU32::new(0);

/// Tabla unica por test; se borra al terminar (tambien si el test entra en panico).
#[derive(Debug)]
pub struct Harness {
    client: Client,
    table: String,
    sessions: Arc<DynamoSessions>,
    pending: Arc<DynamoPending>,
    tickets: Arc<DynamoTickets>,
}

pub fn client() -> Client {
    let endpoint =
        std::env::var("DYNAMODB_ENDPOINT_URL").expect("DYNAMODB_ENDPOINT_URL (DynamoDB Local) no definida");
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-2"))
        .endpoint_url(endpoint)
        .credentials_provider(Credentials::new("test", "test", None, None, "estatica"))
        .build();
    Client::from_conf(config)
}

fn unique_table() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "contrato-{nanos:x}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

impl Harness {
    pub async fn new() -> Self {
        let client = client();
        let table = unique_table();
        let pk = |t| {
            (
                AttributeDefinition::builder()
                    .attribute_name("pk")
                    .attribute_type(t)
                    .build()
                    .unwrap(),
                KeySchemaElement::builder()
                    .attribute_name("pk")
                    .key_type(KeyType::Hash)
                    .build()
                    .unwrap(),
            )
        };
        let (attr, key) = pk(ScalarAttributeType::S);
        client
            .create_table()
            .table_name(&table)
            .attribute_definitions(attr)
            .key_schema(key)
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await
            .expect("create_table");
        client
            .update_time_to_live()
            .table_name(&table)
            .time_to_live_specification(
                TimeToLiveSpecification::builder()
                    .enabled(true)
                    .attribute_name("ttl")
                    .build()
                    .unwrap(),
            )
            .send()
            .await
            .expect("update_time_to_live");
        Self {
            sessions: Arc::new(DynamoSessions::new(client.clone(), &table)),
            pending: Arc::new(DynamoPending::new(client.clone(), &table)),
            tickets: Arc::new(DynamoTickets::new(client.clone(), &table)),
            client,
            table,
        }
    }

    async fn raw(
        &self,
        prefix: &str,
        id: &IdHash,
    ) -> Option<std::collections::HashMap<String, AttributeValue>> {
        self.client
            .get_item()
            .table_name(&self.table)
            .key("pk", AttributeValue::S(format!("{prefix}{}", id.as_str())))
            .consistent_read(true)
            .send()
            .await
            .expect("get_item")
            .item
    }

    async fn ttl(&self, prefix: &str, id: &IdHash) -> Option<Timestamp> {
        let item = self.raw(prefix, id).await?;
        let Some(AttributeValue::N(n)) = item.get("ttl") else {
            panic!("ttl ausente o no numerico");
        };
        Some(Timestamp::from_secs(n.parse().unwrap()))
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let client = self.client.clone();
        let table = self.table.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let _ = client.delete_table().table_name(table).send().await;
            });
        });
    }
}

impl crate::suite::Harness for Harness {
    type Sessions = DynamoSessions;
    type Pending = DynamoPending;
    type Tickets = DynamoTickets;

    fn sessions(&self) -> Arc<DynamoSessions> {
        Arc::clone(&self.sessions)
    }

    fn pending(&self) -> Arc<DynamoPending> {
        Arc::clone(&self.pending)
    }

    fn tickets(&self) -> Arc<DynamoTickets> {
        Arc::clone(&self.tickets)
    }

    async fn session_ttl(&self, id: &IdHash) -> Option<Timestamp> {
        self.ttl("SESSION#", id).await
    }

    async fn session_has_lock_attr(&self, id: &IdHash) -> bool {
        self.raw("SESSION#", id)
            .await
            .is_some_and(|i| i.contains_key("refresh_lock_until"))
    }

    async fn pending_ttl(&self, id: &IdHash) -> Option<Timestamp> {
        self.ttl("PENDING#", id).await
    }

    async fn ticket_ttl(&self, id: &IdHash) -> Option<Timestamp> {
        self.ttl("WSTICKET#", id).await
    }
}
