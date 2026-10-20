//! Conversion entre los tipos de dominio y los items de `DynamoDB`.

use std::collections::HashMap;

use application::ports::AdapterError;
use aws_sdk_dynamodb::types::AttributeValue;
use domain::{
    AccessToken, CodeVerifier, Email, GroupName, IdHash, Nonce, PendingAuth, RefreshToken, ReturnTo, Session,
    State, Subject, Timestamp, TokenSet, UserInfo, Version, WsTicket,
};

pub(crate) type Item = HashMap<String, AttributeValue>;

pub(crate) const PK: &str = "pk";
pub(crate) const VERSION: &str = "version";
pub(crate) const REFRESH_LOCK_UNTIL: &str = "refresh_lock_until";
pub(crate) const TTL: &str = "ttl";

/// Atributo ausente o con forma inesperada. Lleva el nombre del atributo, nunca su valor.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Malformed(pub &'static str);

impl From<Malformed> for AdapterError {
    fn from(m: Malformed) -> Self {
        tracing::error!(attribute = m.0, "item de DynamoDB malformado");
        AdapterError::Permanent
    }
}

// ---------------------------------------------------------------------------------------
// Lectura
// ---------------------------------------------------------------------------------------

fn s<'a>(item: &'a Item, key: &'static str) -> Result<&'a str, Malformed> {
    match item.get(key) {
        Some(AttributeValue::S(v)) => Ok(v),
        _ => Err(Malformed(key)),
    }
}

fn opt_s<'a>(item: &'a Item, key: &'static str) -> Result<Option<&'a str>, Malformed> {
    match item.get(key) {
        None => Ok(None),
        Some(AttributeValue::S(v)) => Ok(Some(v)),
        Some(_) => Err(Malformed(key)),
    }
}

fn parse_u64(v: Option<&AttributeValue>, key: &'static str) -> Result<u64, Malformed> {
    match v {
        Some(AttributeValue::N(n)) => n.parse().map_err(|_| Malformed(key)),
        _ => Err(Malformed(key)),
    }
}

fn n(item: &Item, key: &'static str) -> Result<u64, Malformed> {
    parse_u64(item.get(key), key)
}

fn ts(item: &Item, key: &'static str) -> Result<Timestamp, Malformed> {
    n(item, key).map(Timestamp::from_secs)
}

fn user_from(item: &Item) -> Result<UserInfo, Malformed> {
    let Some(AttributeValue::M(u)) = item.get("user") else {
        return Err(Malformed("user"));
    };
    let sub = Subject::new(s(u, "sub")?.to_owned()).map_err(|_| Malformed("user.sub"))?;
    let email = opt_s(u, "email")?
        .map(|e| Email::new(e.to_owned()))
        .transpose()
        .map_err(|_| Malformed("user.email"))?;
    let name = opt_s(u, "name")?.map(str::to_owned);
    let groups = match u.get("groups") {
        Some(AttributeValue::L(list)) => list
            .iter()
            .map(|g| match g {
                AttributeValue::S(g) => GroupName::new(g.clone()).map_err(|_| Malformed("user.groups")),
                _ => Err(Malformed("user.groups")),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(AttributeValue::Ss(set)) => set
            .iter()
            .map(|g| GroupName::new(g.clone()).map_err(|_| Malformed("user.groups")))
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
        Some(_) => return Err(Malformed("user.groups")),
    };
    let attributes = match u.get("attributes") {
        Some(AttributeValue::M(m)) => m
            .iter()
            .map(|(k, v)| match v {
                AttributeValue::S(v) => Ok((k.clone(), v.clone())),
                _ => Err(Malformed("user.attributes")),
            })
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
        Some(_) => return Err(Malformed("user.attributes")),
    };
    Ok(UserInfo::new(sub, email, name, groups).with_attributes(attributes))
}

fn id_hash_from(item: &Item, prefix: &str) -> Result<IdHash, Malformed> {
    s(item, PK)?
        .strip_prefix(prefix)
        .map(|h| IdHash::from_stored(h.to_owned()))
        .ok_or(Malformed(PK))
}

pub(crate) fn session_from(item: &Item) -> Result<Session, Malformed> {
    let refresh_lock_until = match item.get(REFRESH_LOCK_UNTIL) {
        None => None,
        Some(v) => Some(Timestamp::from_secs(parse_u64(Some(v), REFRESH_LOCK_UNTIL)?)),
    };
    Ok(Session {
        id_hash: id_hash_from(item, super::SESSION_PREFIX)?,
        version: Version::from_stored(n(item, VERSION)?),
        user: user_from(item)?,
        tokens: TokenSet {
            access: AccessToken::new(s(item, "access_token")?.to_owned())
                .map_err(|_| Malformed("access_token"))?,
            refresh: RefreshToken::new(s(item, "refresh_token")?.to_owned())
                .map_err(|_| Malformed("refresh_token"))?,
        },
        access_expires_at: ts(item, "access_expires_at")?,
        absolute_expires_at: ts(item, "absolute_expires_at")?,
        last_seen_at: ts(item, "last_seen_at")?,
        refresh_lock_until,
        created_at: ts(item, "created_at")?,
    })
}

pub(crate) fn pending_from(item: &Item) -> Result<PendingAuth, Malformed> {
    Ok(PendingAuth {
        id_hash: id_hash_from(item, super::PENDING_PREFIX)?,
        state: State::parse(s(item, "state")?).map_err(|_| Malformed("state"))?,
        nonce: Nonce::parse(s(item, "nonce")?).map_err(|_| Malformed("nonce"))?,
        code_verifier: CodeVerifier::parse(s(item, "code_verifier")?)
            .map_err(|_| Malformed("code_verifier"))?,
        return_to: ReturnTo::parse(s(item, "return_to")?).map_err(|_| Malformed("return_to"))?,
        created_at: ts(item, "created_at")?,
    })
}

pub(crate) fn ticket_from(item: &Item) -> Result<WsTicket, Malformed> {
    Ok(WsTicket {
        id_hash: id_hash_from(item, super::WSTICKET_PREFIX)?,
        session_hash: IdHash::from_stored(s(item, "session_hash")?.to_owned()),
        user: user_from(item)?,
        created_at: ts(item, "created_at")?,
    })
}

// ---------------------------------------------------------------------------------------
// Escritura
// ---------------------------------------------------------------------------------------

pub(crate) fn num(v: u64) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

fn text(v: &str) -> AttributeValue {
    AttributeValue::S(v.to_owned())
}

pub(crate) fn key(prefix: &str, id: &IdHash) -> Item {
    HashMap::from([(PK.to_owned(), text(&format!("{prefix}{}", id.as_str())))])
}

fn user_to(u: &UserInfo) -> AttributeValue {
    let mut m = HashMap::from([("sub".to_owned(), text(u.sub().as_str()))]);
    if let Some(e) = u.email() {
        m.insert("email".to_owned(), text(e.as_str()));
    }
    if let Some(name) = u.name() {
        m.insert("name".to_owned(), text(name));
    }
    m.insert(
        "groups".to_owned(),
        AttributeValue::L(u.groups().iter().map(|g| text(g.as_str())).collect()),
    );
    m.insert(
        "attributes".to_owned(),
        AttributeValue::M(u.attributes().iter().map(|(k, v)| (k.clone(), text(v))).collect()),
    );
    AttributeValue::M(m)
}

/// Item completo de una sesion. `refresh_lock_until` solo aparece si hay lease.
pub(crate) fn session_to(prefix: &str, s: &Session, ttl: Timestamp) -> Item {
    let mut item = key(prefix, &s.id_hash);
    item.insert(VERSION.to_owned(), num(s.version.get()));
    item.insert("user".to_owned(), user_to(&s.user));
    item.insert("access_token".to_owned(), text(s.tokens.access.expose_secret()));
    item.insert("refresh_token".to_owned(), text(s.tokens.refresh.expose_secret()));
    item.insert("access_expires_at".to_owned(), num(s.access_expires_at.as_secs()));
    item.insert(
        "absolute_expires_at".to_owned(),
        num(s.absolute_expires_at.as_secs()),
    );
    item.insert("last_seen_at".to_owned(), num(s.last_seen_at.as_secs()));
    if let Some(l) = s.refresh_lock_until {
        item.insert(REFRESH_LOCK_UNTIL.to_owned(), num(l.as_secs()));
    }
    item.insert("created_at".to_owned(), num(s.created_at.as_secs()));
    item.insert(TTL.to_owned(), num(ttl.as_secs()));
    item
}

pub(crate) fn pending_to(prefix: &str, p: &PendingAuth, ttl: Timestamp) -> Item {
    let mut item = key(prefix, &p.id_hash);
    item.insert("state".to_owned(), text(&p.state.expose_secret()));
    item.insert("nonce".to_owned(), text(&p.nonce.expose_secret()));
    item.insert("code_verifier".to_owned(), text(p.code_verifier.expose_secret()));
    item.insert("return_to".to_owned(), text(p.return_to.as_str()));
    item.insert("created_at".to_owned(), num(p.created_at.as_secs()));
    item.insert(TTL.to_owned(), num(ttl.as_secs()));
    item
}

pub(crate) fn ticket_to(prefix: &str, t: &WsTicket, ttl: Timestamp) -> Item {
    let mut item = key(prefix, &t.id_hash);
    item.insert("session_hash".to_owned(), text(t.session_hash.as_str()));
    item.insert("user".to_owned(), user_to(&t.user));
    item.insert("created_at".to_owned(), num(t.created_at.as_secs()));
    item.insert(TTL.to_owned(), num(ttl.as_secs()));
    item
}
