use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::DomainError;
use crate::ids::{RANDOM_ID_BYTES, ct_eq_str, encode, random_id};

random_id!(
    /// Parametro `state` de OAuth 2.0. Se compara en tiempo constante en el callback.
    State
);

random_id!(
    /// `nonce` de OIDC: liga el ID token a este login.
    Nonce
);

impl Nonce {
    /// Compara contra el claim `nonce` del ID token, en tiempo constante.
    pub fn matches_claim(&self, claim: &str) -> bool {
        ct_eq_str(&self.expose_secret(), claim)
    }
}

const VERIFIER_MIN_LEN: usize = 43;
const VERIFIER_MAX_LEN: usize = 128;

/// `code_verifier` de PKCE (RFC 7636 §4.1): 43–128 caracteres no reservados.
#[derive(Clone)]
pub struct CodeVerifier(Zeroizing<String>);

impl CodeVerifier {
    /// 32 bytes del CSPRNG en base64url: 43 caracteres, 256 bits de entropia.
    pub fn from_bytes(bytes: [u8; RANDOM_ID_BYTES]) -> Self {
        let bytes = Zeroizing::new(bytes);
        Self(Zeroizing::new(encode(&bytes[..])))
    }

    /// Valida un valor leido del almacen.
    ///
    /// # Errors
    /// `DomainError::InvalidCodeVerifier` si no cumple RFC 7636.
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        let ok = (VERIFIER_MIN_LEN..=VERIFIER_MAX_LEN).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
        if ok {
            Ok(Self(Zeroizing::new(s.to_owned())))
        } else {
            Err(DomainError::InvalidCodeVerifier)
        }
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// `code_challenge` con metodo `S256`.
    pub fn challenge(&self) -> CodeChallenge {
        CodeChallenge(encode(&Sha256::digest(self.0.as_bytes())))
    }
}

impl core::fmt::Debug for CodeVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CodeVerifier([REDACTED])")
    }
}

/// `code_challenge` S256. Viaja en claro en la URL de autorizacion; no es secreto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeChallenge(String);

impl CodeChallenge {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_s256_vector_rfc7636() {
        // RFC 7636, apendice B.
        let v = CodeVerifier::parse("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap();
        assert_eq!(
            v.challenge().as_str(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn verifier_generado_es_valido() {
        let v = CodeVerifier::from_bytes([9u8; RANDOM_ID_BYTES]);
        assert!(CodeVerifier::parse(v.expose_secret()).is_ok());
    }

    #[test]
    fn verifier_rechaza_invalidos() {
        for c in [
            "",
            &"a".repeat(42),
            &"a".repeat(129),
            &format!("{}+", "a".repeat(42)),
            &format!("{} ", "a".repeat(42)),
        ] {
            assert_eq!(
                CodeVerifier::parse(c).err(),
                Some(DomainError::InvalidCodeVerifier)
            );
        }
    }

    #[test]
    fn debug_redactado() {
        let v = CodeVerifier::from_bytes([9u8; RANDOM_ID_BYTES]);
        assert_eq!(format!("{v:?}"), "CodeVerifier([REDACTED])");
        assert_eq!(
            format!("{:?}", State::from_bytes([1u8; RANDOM_ID_BYTES])),
            "State([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", Nonce::from_bytes([1u8; RANDOM_ID_BYTES])),
            "Nonce([REDACTED])"
        );
    }

    #[test]
    fn nonce_compara_claim() {
        let n = Nonce::from_bytes([3u8; RANDOM_ID_BYTES]);
        assert!(n.matches_claim(&n.expose_secret()));
        assert!(!n.matches_claim("otro"));
        assert!(!n.matches_claim(""));
    }

    #[test]
    fn state_distinto_no_coincide() {
        let a = State::from_bytes([1u8; RANDOM_ID_BYTES]);
        let b = State::from_bytes([2u8; RANDOM_ID_BYTES]);
        assert!(!a.ct_eq(&b));
        assert!(a.ct_eq(&State::parse(&a.expose_secret()).unwrap()));
    }
}
