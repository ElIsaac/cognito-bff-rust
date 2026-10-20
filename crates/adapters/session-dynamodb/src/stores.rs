use application::ports::{AdapterError, PendingAuthStore, WsTicketStore};
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::types::ReturnValue;
use domain::{IdHash, PendingAuth, Timestamp, WsTicket};

use crate::codec::{self, Item};
use crate::error::{classify, is_conditional_failure};
use crate::{PENDING_PREFIX, WSTICKET_PREFIX};

async fn put(client: &Client, table: &str, op: &'static str, item: Item) -> Result<(), AdapterError> {
    client
        .put_item()
        .table_name(table)
        .set_item(Some(item))
        .condition_expression("attribute_not_exists(pk)")
        .send()
        .await
        .map_err(|e| classify(op, &e))?;
    Ok(())
}

/// Lectura y borrado atomicos: un solo `DeleteItem` con `ALL_OLD`.
///
/// Lleva `attribute_exists(pk)`: en `DynamoDB` real no cambia nada (si no existia, `ALL_OLD`
/// ya viene vacio), pero `DynamoDB` Local sin condicion devuelve el item a varios
/// borrados concurrentes; con la condicion el borrado se serializa tambien alli.
async fn consume(
    client: &Client,
    table: &str,
    op: &'static str,
    prefix: &str,
    id: &IdHash,
) -> Result<Option<Item>, AdapterError> {
    let res = client
        .delete_item()
        .table_name(table)
        .set_key(Some(codec::key(prefix, id)))
        .condition_expression("attribute_exists(pk)")
        .return_values(ReturnValue::AllOld)
        .send()
        .await;
    match res {
        Ok(out) => Ok(out.attributes),
        Err(e) if is_conditional_failure(&e) => Ok(None),
        Err(e) => Err(classify(op, &e)),
    }
}

/// `PendingAuthStore` sobre `DynamoDB`.
#[derive(Debug, Clone)]
pub struct DynamoPending {
    client: Client,
    table: String,
}

impl DynamoPending {
    pub fn new(client: Client, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }
}

impl PendingAuthStore for DynamoPending {
    async fn put(&self, p: &PendingAuth, ttl: Timestamp) -> Result<(), AdapterError> {
        put(
            &self.client,
            &self.table,
            "pending.put",
            codec::pending_to(PENDING_PREFIX, p, ttl),
        )
        .await
    }

    async fn consume(&self, id: &IdHash) -> Result<Option<PendingAuth>, AdapterError> {
        consume(&self.client, &self.table, "pending.consume", PENDING_PREFIX, id)
            .await?
            .map(|item| codec::pending_from(&item).map_err(AdapterError::from))
            .transpose()
    }
}

/// `WsTicketStore` sobre `DynamoDB`.
#[derive(Debug, Clone)]
pub struct DynamoTickets {
    client: Client,
    table: String,
}

impl DynamoTickets {
    pub fn new(client: Client, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }
}

impl WsTicketStore for DynamoTickets {
    async fn put(&self, t: &WsTicket, ttl: Timestamp) -> Result<(), AdapterError> {
        put(
            &self.client,
            &self.table,
            "ticket.put",
            codec::ticket_to(WSTICKET_PREFIX, t, ttl),
        )
        .await
    }

    async fn consume(&self, id: &IdHash) -> Result<Option<WsTicket>, AdapterError> {
        consume(&self.client, &self.table, "ticket.consume", WSTICKET_PREFIX, id)
            .await?
            .map(|item| codec::ticket_from(&item).map_err(AdapterError::from))
            .transpose()
    }
}
