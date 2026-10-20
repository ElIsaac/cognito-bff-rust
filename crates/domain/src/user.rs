use std::collections::BTreeMap;
use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::DomainError;

const SUBJECT_MAX_LEN: usize = 128;
/// Bytes del sha256 del `sub` que se dejan en los logs.
const LOG_HASH_BYTES: usize = 8;
const EMAIL_MAX_LEN: usize = 254;
const GROUP_MAX_LEN: usize = 128;
const NAME_MAX_LEN: usize = 256;
const GROUPS_MAX: usize = 100;
const ATTRIBUTES_MAX: usize = 20;
const ATTRIBUTE_KEY_MAX_LEN: usize = 64;
const ATTRIBUTE_VALUE_MAX_LEN: usize = 256;

fn printable_no_space(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_graphic())
}

/// Claim `sub` de Cognito.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject(String);

impl Subject {
    /// # Errors
    /// `DomainError::InvalidSubject` si esta vacio, excede 128 bytes o no es ASCII visible.
    pub fn new(value: String) -> Result<Self, DomainError> {
        if !value.is_empty() && value.len() <= SUBJECT_MAX_LEN && printable_no_space(&value) {
            Ok(Self(value))
        } else {
            Err(DomainError::InvalidSubject)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Huella para los logs: los primeros 8 bytes del sha256 del `sub`, en hexadecimal.
    pub fn log_hash(&self) -> String {
        Sha256::digest(self.0.as_bytes())
            .iter()
            .take(LOG_HASH_BYTES)
            .fold(String::with_capacity(2 * LOG_HASH_BYTES), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}

/// Email ya verificado por Cognito; aqui solo se acota su forma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email(String);

impl Email {
    /// # Errors
    /// `DomainError::InvalidEmail` si no tiene exactamente una `@` con texto a ambos lados,
    /// excede 254 bytes o tiene espacios o controles.
    pub fn new(value: String) -> Result<Self, DomainError> {
        let ok = value.len() <= EMAIL_MAX_LEN
            && !value.chars().any(|c| c.is_whitespace() || c.is_control())
            && matches!(value.split_once('@'), Some((l, d)) if !l.is_empty() && !d.is_empty() && !d.contains('@'));
        if ok {
            Ok(Self(value))
        } else {
            Err(DomainError::InvalidEmail)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Grupo de Cognito (claim `cognito:groups`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupName(String);

impl GroupName {
    /// # Errors
    /// `DomainError::InvalidGroupName` si esta vacio, excede 128 bytes o tiene espacios o
    /// controles.
    pub fn new(value: String) -> Result<Self, DomainError> {
        let ok = !value.is_empty()
            && value.len() <= GROUP_MAX_LEN
            && !value.chars().any(|c| c.is_whitespace() || c.is_control());
        if ok {
            Ok(Self(value))
        } else {
            Err(DomainError::InvalidGroupName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Datos del usuario extraidos del ID token validado. Es lo que devuelve `/auth/me`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    sub: Subject,
    email: Option<Email>,
    name: Option<String>,
    groups: Vec<GroupName>,
    attributes: BTreeMap<String, String>,
}

impl UserInfo {
    /// El nombre se descarta (no se rechaza el login) si es demasiado largo o trae
    /// controles; los grupos se acotan a los primeros 100.
    pub fn new(sub: Subject, email: Option<Email>, name: Option<String>, mut groups: Vec<GroupName>) -> Self {
        let name = name.filter(|n| n.len() <= NAME_MAX_LEN && !n.chars().any(char::is_control));
        groups.truncate(GROUPS_MAX);
        Self {
            sub,
            email,
            name,
            groups,
            attributes: BTreeMap::new(),
        }
    }

    /// Claims adicionales de una lista blanca configurada (p. ej. `custom:tenant_id`).
    /// Se descartan en silencio las entradas con clave o valor fuera de forma y todo lo que
    /// pase de 20 entradas.
    #[must_use]
    pub fn with_attributes(mut self, attributes: impl IntoIterator<Item = (String, String)>) -> Self {
        self.attributes = attributes
            .into_iter()
            .filter(|(k, v)| {
                !k.is_empty()
                    && k.len() <= ATTRIBUTE_KEY_MAX_LEN
                    && printable_no_space(k)
                    && v.len() <= ATTRIBUTE_VALUE_MAX_LEN
                    && !v.chars().any(char::is_control)
            })
            .take(ATTRIBUTES_MAX)
            .collect();
        self
    }

    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    pub fn sub(&self) -> &Subject {
        &self.sub
    }

    pub fn email(&self) -> Option<&Email> {
        self.email.as_ref()
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn groups(&self) -> &[GroupName] {
        &self.groups
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email() {
        assert!(Email::new("a@b.com".into()).is_ok());
        for bad in ["", "ab.com", "@b.com", "a@", "a@b@c", "a b@c.com", "a@b.com\n"] {
            assert!(Email::new(bad.into()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn subject_y_grupo() {
        assert!(Subject::new("1b2c-3d".into()).is_ok());
        assert!(Subject::new(String::new()).is_err());
        assert!(Subject::new("a b".into()).is_err());
        assert!(GroupName::new("dueno".into()).is_ok());
        assert!(GroupName::new("a\u{0}".into()).is_err());
        assert!(GroupName::new("x".repeat(129)).is_err());
    }

    #[test]
    fn huella_del_sub_para_logs() {
        // sha256("abc") = ba7816bf 8f01cfea ...
        let h = Subject::new("abc".into()).unwrap().log_hash();
        assert_eq!(h, "ba7816bf8f01cfea");
        assert!(!h.contains("abc"));
        let otro = Subject::new("abd".into()).unwrap().log_hash();
        assert_ne!(h, otro);
    }

    #[test]
    fn nombre_con_controles_se_descarta() {
        let u = UserInfo::new(
            Subject::new("s".into()).unwrap(),
            None,
            Some("a\u{1b}[31m".into()),
            vec![],
        );
        assert_eq!(u.name(), None);
    }

    #[test]
    fn atributos_filtrados() {
        let u = UserInfo::new(Subject::new("s".into()).unwrap(), None, None, vec![]).with_attributes([
            ("custom:tenant_id".into(), "t1".into()),
            ("con espacio".into(), "x".into()),
            ("k".into(), "a\nb".into()),
        ]);
        assert_eq!(u.attributes().len(), 1);
        assert_eq!(
            u.attributes().get("custom:tenant_id").map(String::as_str),
            Some("t1")
        );
    }
}
