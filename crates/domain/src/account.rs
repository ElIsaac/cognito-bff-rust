use secrecy::{ExposeSecret, SecretString};

use crate::DomainError;

/// Tope de longitud de una contrasena (Cognito admite hasta 256).
const PASSWORD_MAX_LEN: usize = 256;
/// Tope de longitud del secreto TOTP que devuelve Cognito (base32).
const TOTP_SECRET_MAX_LEN: usize = 256;
/// Digitos de un codigo TOTP de Cognito.
const TOTP_CODE_LEN: usize = 6;
/// Tope del nombre legible del dispositivo TOTP.
const DEVICE_NAME_MAX_LEN: usize = 64;

/// Contrasena del usuario, solo de paso hacia Cognito. Nunca se guarda.
#[derive(Clone)]
pub struct Password(SecretString);

impl Password {
    /// # Errors
    /// `DomainError::InvalidPassword` si esta vacia, pasa de 256 caracteres o tiene
    /// caracteres de control.
    pub fn new(value: String) -> Result<Self, DomainError> {
        let ok = !value.is_empty()
            && value.chars().count() <= PASSWORD_MAX_LEN
            && !value.chars().any(char::is_control);
        if ok {
            Ok(Self(SecretString::from(value)))
        } else {
            Err(DomainError::InvalidPassword)
        }
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password([REDACTED])")
    }
}

/// Codigo de 6 digitos de una app de autenticacion.
#[derive(Clone)]
pub struct TotpCode(SecretString);

impl TotpCode {
    /// # Errors
    /// `DomainError::InvalidTotpCode` si no son exactamente 6 digitos ASCII.
    pub fn new(value: String) -> Result<Self, DomainError> {
        if value.len() == TOTP_CODE_LEN && value.bytes().all(|b| b.is_ascii_digit()) {
            Ok(Self(SecretString::from(value)))
        } else {
            Err(DomainError::InvalidTotpCode)
        }
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpCode([REDACTED])")
    }
}

/// Secreto TOTP recien asociado. Sale una sola vez hacia el usuario para su app.
#[derive(Clone)]
pub struct TotpSecret(SecretString);

impl TotpSecret {
    /// # Errors
    /// `DomainError::InvalidToken` si esta vacio, es demasiado largo o no es base32.
    pub fn new(value: String) -> Result<Self, DomainError> {
        let ok = !value.is_empty()
            && value.len() <= TOTP_SECRET_MAX_LEN
            && value
                .bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b) || b == b'=');
        if ok {
            Ok(Self(SecretString::from(value)))
        } else {
            Err(DomainError::InvalidToken)
        }
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSecret([REDACTED])")
    }
}

/// Nombre legible del dispositivo TOTP (no es secreto).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceName(String);

impl DeviceName {
    /// Recorta espacios; vacio tras recortar se trata como ausente.
    ///
    /// # Errors
    /// `DomainError::InvalidDeviceName` si pasa de 64 caracteres o tiene caracteres de
    /// control.
    pub fn parse(value: &str) -> Result<Option<Self>, DomainError> {
        let v = value.trim();
        if v.is_empty() {
            return Ok(None);
        }
        if v.chars().count() > DEVICE_NAME_MAX_LEN || v.chars().any(char::is_control) {
            return Err(DomainError::InvalidDeviceName);
        }
        Ok(Some(Self(v.to_owned())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password() {
        assert!(Password::new("Correcta-1 con espacios".into()).is_ok());
        assert!(Password::new(String::new()).is_err());
        assert!(Password::new("a\nb".into()).is_err());
        assert!(Password::new("x".repeat(257)).is_err());
        assert!(Password::new("ñ".repeat(256)).is_ok());
        let dbg = format!("{:?}", Password::new("secreta-123".into()).unwrap());
        assert!(!dbg.contains("secreta"), "{dbg}");
    }

    #[test]
    fn totp_code() {
        assert!(TotpCode::new("012345".into()).is_ok());
        for malo in ["12345", "1234567", "12a456", "１２３４５６", " 12345"] {
            assert!(TotpCode::new(malo.into()).is_err(), "{malo}");
        }
        assert_eq!(
            format!("{:?}", TotpCode::new("123456".into()).unwrap()),
            "TotpCode([REDACTED])"
        );
    }

    #[test]
    fn totp_secret() {
        assert!(TotpSecret::new("JBSWY3DPEHPK3PXP".into()).is_ok());
        assert!(TotpSecret::new("jbswy3dp".into()).is_err());
        assert!(TotpSecret::new("JBSW1".into()).is_err());
        assert!(TotpSecret::new(String::new()).is_err());
        let dbg = format!("{:?}", TotpSecret::new("JBSWY3DPEHPK3PXP".into()).unwrap());
        assert!(!dbg.contains("JBSW"), "{dbg}");
    }

    #[test]
    fn device_name() {
        assert_eq!(DeviceName::parse("  ").unwrap(), None);
        assert_eq!(DeviceName::parse(" Mi tel ").unwrap().unwrap().as_str(), "Mi tel");
        assert!(DeviceName::parse(&"x".repeat(65)).is_err());
        assert!(DeviceName::parse("a\u{0}b").is_err());
    }
}
