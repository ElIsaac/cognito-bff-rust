use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::DomainError;

/// Bytes de entropia de todo identificador aleatorio (256 bits).
pub const RANDOM_ID_BYTES: usize = 32;

/// Longitud en base64url sin relleno de `RANDOM_ID_BYTES` bytes.
pub(crate) const RANDOM_ID_ENCODED_LEN: usize = 43;

pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodifica exactamente `RANDOM_ID_BYTES` bytes desde base64url canonico sin relleno.
/// Rechaza longitudes distintas, caracteres fuera del alfabeto y bits sobrantes no nulos
/// (dos cadenas distintas nunca decodifican al mismo identificador).
pub(crate) fn decode_random_id(s: &str) -> Result<Zeroizing<[u8; RANDOM_ID_BYTES]>, DomainError> {
    if s.len() != RANDOM_ID_ENCODED_LEN
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(DomainError::InvalidRandomId);
    }
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| DomainError::InvalidRandomId)?,
    );
    let mut out = Zeroizing::new([0u8; RANDOM_ID_BYTES]);
    if decoded.len() != RANDOM_ID_BYTES {
        return Err(DomainError::InvalidRandomId);
    }
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Huella de un identificador: `base64url(sha256(bytes))`. Es lo unico que se guarda como
/// clave en el almacen; no es sensible.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdHash(String);

impl IdHash {
    pub(crate) fn of(bytes: &[u8]) -> Self {
        Self(encode(&Sha256::digest(bytes)))
    }

    /// Reconstruye una huella leida del almacen.
    pub fn from_stored(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Define un identificador aleatorio de `RANDOM_ID_BYTES` bytes con `Debug` redactado,
/// sin `Display`, comparacion en tiempo constante y huella SHA-256.
macro_rules! random_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name(::zeroize::Zeroizing<[u8; $crate::ids::RANDOM_ID_BYTES]>);

        impl $name {
            /// Construye el valor a partir de bytes del CSPRNG.
            pub fn from_bytes(bytes: [u8; $crate::ids::RANDOM_ID_BYTES]) -> Self {
                Self(::zeroize::Zeroizing::new(bytes))
            }

            /// Valida un valor recibido (cookie, query o almacen).
            ///
            /// # Errors
            /// `DomainError::InvalidRandomId` si no son 43 caracteres base64url canonicos.
            pub fn parse(s: &str) -> Result<Self, $crate::DomainError> {
                $crate::ids::decode_random_id(s).map(Self)
            }

            /// Valor en base64url para la cookie, la URL de autorizacion o el almacen.
            /// Nunca debe llegar a un log.
            pub fn expose_secret(&self) -> String {
                $crate::ids::encode(&self.0[..])
            }

            pub fn hash(&self) -> $crate::IdHash {
                $crate::IdHash::of(&self.0[..])
            }

            /// Comparacion en tiempo constante.
            pub fn ct_eq(&self, other: &Self) -> bool {
                ::subtle::ConstantTimeEq::ct_eq(&self.0[..], &other.0[..]).into()
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}
pub(crate) use random_id;

random_id!(
    /// Identificador de sesion: valor de la cookie `__Host-bff_session`.
    SessionId
);

random_id!(
    /// Identificador del login en curso: valor de la cookie `__Host-bff_pending`.
    PendingId
);

/// Comparacion en tiempo constante de cadenas arbitrarias (longitudes distintas ⇒ falso).
pub(crate) fn ct_eq_str(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYTES: [u8; RANDOM_ID_BYTES] = [7u8; RANDOM_ID_BYTES];

    #[test]
    fn roundtrip_por_cookie() {
        let id = SessionId::from_bytes(BYTES);
        let s = id.expose_secret();
        assert_eq!(s.len(), RANDOM_ID_ENCODED_LEN);
        assert!(SessionId::parse(&s).is_ok_and(|p| p.ct_eq(&id)));
    }

    #[test]
    fn rechaza_formatos_invalidos() {
        let ok = SessionId::from_bytes(BYTES).expose_secret();
        let casos = [
            String::new(),
            ok[..42].to_string(),
            format!("{ok}A"),
            format!("{}=", &ok[..42]),
            ok.replace('B', "+"),
            format!("{}/", &ok[..42]),
            format!("{} ", &ok[..42]),
            format!("{}\u{e9}", &ok[..41]),
            "A".repeat(10_000),
        ];
        for c in casos {
            assert_eq!(
                SessionId::parse(&c).err(),
                Some(DomainError::InvalidRandomId),
                "{c:?}"
            );
        }
    }

    #[test]
    fn rechaza_bits_sobrantes_no_canonicos() {
        let ok = SessionId::from_bytes([0u8; RANDOM_ID_BYTES]).expose_secret();
        let mut alterado = ok[..42].to_string();
        alterado.push('B');
        assert!(SessionId::parse(&alterado).is_err());
    }

    #[test]
    fn debug_redactado() {
        let id = SessionId::from_bytes(BYTES);
        let dbg = format!("{id:?}");
        assert_eq!(dbg, "SessionId([REDACTED])");
        assert!(!dbg.contains(&id.expose_secret()));
    }

    #[test]
    fn huella_estable_y_distinta_del_valor() {
        let id = PendingId::from_bytes(BYTES);
        assert_eq!(id.hash(), PendingId::from_bytes(BYTES).hash());
        assert_ne!(id.hash().as_str(), id.expose_secret());
        assert_ne!(id.hash(), PendingId::from_bytes([8u8; RANDOM_ID_BYTES]).hash());
    }

    #[test]
    fn ct_eq_str_basico() {
        assert!(ct_eq_str("abc", "abc"));
        assert!(!ct_eq_str("abc", "abd"));
        assert!(!ct_eq_str("abc", "abcd"));
    }
}
