use secrecy::{ExposeSecret, SecretString};

use crate::DomainError;

/// Tope de longitud de un token de Cognito (los JWT reales rondan 1–4 KiB).
const TOKEN_MAX_LEN: usize = 16 * 1024;

macro_rules! token {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name(SecretString);

        impl $name {
            /// # Errors
            /// `DomainError::InvalidToken` si esta vacio, es demasiado largo o tiene
            /// caracteres fuera de ASCII imprimible sin espacios.
            pub fn new(value: String) -> Result<Self, DomainError> {
                let ok = !value.is_empty()
                    && value.len() <= TOKEN_MAX_LEN
                    && value.bytes().all(|b| b.is_ascii_graphic());
                if ok {
                    Ok(Self(SecretString::from(value)))
                } else {
                    Err(DomainError::InvalidToken)
                }
            }

            /// Valor en claro. Solo para la cabecera `Authorization` o el almacen.
            pub fn expose_secret(&self) -> &str {
                self.0.expose_secret()
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

token!(
    /// Access token de Cognito: se reenvia a la API upstream y nunca sale al navegador.
    AccessToken
);

token!(
    /// Refresh token de Cognito.
    RefreshToken
);

token!(
    /// `code` de autorizacion recibido en el callback. De un solo uso, pero secreto hasta
    /// que se canjea.
    AuthCode
);

/// Tokens de una sesion. El ID token no se guarda: sus claims ya validados viven en
/// `UserInfo`.
#[derive(Debug, Clone)]
pub struct TokenSet {
    pub access: AccessToken,
    pub refresh: RefreshToken,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redactado() {
        let t = TokenSet {
            access: AccessToken::new("eyJ.acceso.secreto".into()).unwrap(),
            refresh: RefreshToken::new("refresco-secreto".into()).unwrap(),
        };
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("secreto"), "{dbg}");
        assert!(dbg.contains("AccessToken([REDACTED])"));
        assert!(dbg.contains("RefreshToken([REDACTED])"));
    }

    #[test]
    fn rechaza_invalidos() {
        for bad in [
            String::new(),
            "a b".into(),
            "a\nb".into(),
            "x".repeat(TOKEN_MAX_LEN + 1),
        ] {
            assert_eq!(AccessToken::new(bad).err(), Some(DomainError::InvalidToken));
        }
    }
}
