use application::ports::{AdapterError, LeaseOutcome, SessionRepository, UpdateOutcome};
use aws_sdk_dynamodb::Client;
use domain::{IdHash, Session, Timestamp, Version};

use crate::SESSION_PREFIX;
use crate::codec::{self, VERSION};
use crate::error::{classify, is_conditional_failure};

/// `SessionRepository` sobre `DynamoDB`.
#[derive(Debug, Clone)]
pub struct DynamoSessions {
    client: Client,
    table: String,
}

impl DynamoSessions {
    pub fn new(client: Client, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }
}

impl SessionRepository for DynamoSessions {
    async fn get(&self, id: &IdHash) -> Result<Option<Session>, AdapterError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .set_key(Some(codec::key(SESSION_PREFIX, id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| classify("session.get", &e))?;
        out.item()
            .map(|item| codec::session_from(item).map_err(AdapterError::from))
            .transpose()
    }

    async fn create(&self, s: &Session, ttl: Timestamp) -> Result<(), AdapterError> {
        self.client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(codec::session_to(SESSION_PREFIX, s, ttl)))
            .condition_expression("attribute_not_exists(pk)")
            .send()
            .await
            .map_err(|e| classify("session.create", &e))?;
        Ok(())
    }

    async fn update_if_version(
        &self,
        s: &Session,
        expected: Version,
        ttl: Timestamp,
    ) -> Result<UpdateOutcome, AdapterError> {
        let res = self
            .client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(codec::session_to(SESSION_PREFIX, s, ttl)))
            .condition_expression("attribute_exists(pk) AND #v = :expected")
            .expression_attribute_names("#v", VERSION)
            .expression_attribute_values(":expected", codec::num(expected.get()))
            .send()
            .await;
        match res {
            Ok(_) => Ok(UpdateOutcome::Updated),
            Err(e) if is_conditional_failure(&e) => Ok(UpdateOutcome::Conflict),
            Err(e) => Err(classify("session.update", &e)),
        }
    }

    async fn acquire_refresh_lease(
        &self,
        id: &IdHash,
        expected: Version,
        now: Timestamp,
        until: Timestamp,
    ) -> Result<LeaseOutcome, AdapterError> {
        let next = expected.next();
        let res = self
            .client
            .update_item()
            .table_name(&self.table)
            .set_key(Some(codec::key(SESSION_PREFIX, id)))
            .update_expression("SET refresh_lock_until = :until, #v = :next")
            .condition_expression(
                "attribute_exists(pk) AND #v = :expected AND \
                 (attribute_not_exists(refresh_lock_until) OR refresh_lock_until < :now)",
            )
            .expression_attribute_names("#v", VERSION)
            .expression_attribute_values(":until", codec::num(until.as_secs()))
            .expression_attribute_values(":next", codec::num(next.get()))
            .expression_attribute_values(":expected", codec::num(expected.get()))
            .expression_attribute_values(":now", codec::num(now.as_secs()))
            .send()
            .await;
        match res {
            Ok(_) => Ok(LeaseOutcome::Acquired { version: next }),
            Err(e) if is_conditional_failure(&e) => Ok(LeaseOutcome::Conflict),
            Err(e) => Err(classify("session.lease", &e)),
        }
    }

    async fn delete(&self, id: &IdHash) -> Result<(), AdapterError> {
        self.client
            .delete_item()
            .table_name(&self.table)
            .set_key(Some(codec::key(SESSION_PREFIX, id)))
            .send()
            .await
            .map_err(|e| classify("session.delete", &e))?;
        Ok(())
    }
}
