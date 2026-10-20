use crate::DomainError;

/// Longitud maxima de `returnTo`.
pub const RETURN_TO_MAX_LEN: usize = 2048;

/// Bytes que un `%XX` no puede codificar: separadores de ruta (`/`, `\`), punto (segmentos
/// `.`/`..`), NUL, CR, LF y el resto de controles.
fn forbidden_encoded(byte: u8) -> bool {
    matches!(byte, b'/' | b'\\' | b'.') || byte < 0x20 || byte == 0x7F
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Ruta relativa al origen publico a la que se vuelve tras el login.
///
/// Reglas (todo lo demas se rechaza):
/// 1. ASCII imprimible (0x20–0x7E), sin `\`, longitud ≤ `RETURN_TO_MAX_LEN`.
/// 2. Empieza por exactamente un `/`; el segundo caracter no es `/` ni `\`.
/// 3. Todo `%` va seguido de dos hexadecimales y no codifica `/`, `\`, `.` ni un control.
/// 4. Sin `@` antes del primer `?`.
/// 5. Se valida el valor tal como llega tras la unica decodificacion de la query; nunca se
///    decodifica otra vez.
///
/// Con estas reglas, `PUBLIC_ORIGIN + returnTo` siempre conserva el host de `PUBLIC_ORIGIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnTo(String);

impl ReturnTo {
    /// # Errors
    /// `DomainError::InvalidReturnTo` si incumple alguna regla.
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        let b = s.as_bytes();
        let err = Err(DomainError::InvalidReturnTo);

        if b.is_empty() || b.len() > RETURN_TO_MAX_LEN {
            return err;
        }
        if !b.iter().all(|&c| (0x20..=0x7E).contains(&c) && c != b'\\') {
            return err;
        }
        if b[0] != b'/' || b.get(1) == Some(&b'/') {
            return err;
        }

        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                let (Some(hi), Some(lo)) = (
                    b.get(i + 1).copied().and_then(hex_value),
                    b.get(i + 2).copied().and_then(hex_value),
                ) else {
                    return err;
                };
                if forbidden_encoded(hi << 4 | lo) {
                    return err;
                }
                i += 3;
            } else {
                i += 1;
            }
        }

        let before_query = s.split('?').next().unwrap_or(s);
        if before_query.contains('@') {
            return err;
        }

        Ok(Self(s.to_owned()))
    }

    /// `returnTo` de la query: si falta o es invalido se usa `/`.
    pub fn parse_or_default(s: Option<&str>) -> Self {
        s.and_then(|v| Self::parse(v).ok()).unwrap_or_default()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ReturnTo {
    fn default() -> Self {
        Self("/".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ORIGIN: &str = "https://app.example.com";

    #[test]
    fn acepta_rutas_normales() {
        for ok in [
            "/",
            "/ventas",
            "/ventas/2026?mes=10&x=a%20b",
            "/a-b_c~d",
            "/ruta#ancla",
            "/buscar?correo=a@b.com",
            "/%E2%9C%93",
        ] {
            assert_eq!(
                ReturnTo::parse(ok).map(|r| r.as_str().to_owned()),
                Ok(ok.to_owned())
            );
        }
    }

    #[test]
    fn rechaza_ataques_conocidos() {
        let largo = format!("/{}", "a".repeat(10_000));
        for bad in [
            "",
            "https://evil.com",
            "http://evil.com",
            "//evil.com",
            "/\\evil.com",
            "\\\\evil.com",
            "\\/evil.com",
            "/%2F%2Fevil.com",
            "/%2f%2fevil.com",
            "/%5Cevil.com",
            "/%5cevil.com",
            "javascript:alert(1)",
            "data:text/html,x",
            "/@evil.com",
            "/x@evil.com",
            "/x%0d%0aSet-Cookie:a=b",
            "/x%0D%0A",
            "/x\0",
            "/x\r\nSet-Cookie: a=b",
            "/x\tevil",
            "/%00",
            "/%2e%2e/",
            "/%2E%2E/admin",
            "/%",
            "/%2",
            "/%zz",
            "/%%32%46",
            "/\u{7f}",
            "/caf\u{e9}",
            "evil.com",
            " /x",
            &largo,
        ] {
            assert_eq!(ReturnTo::parse(bad), Err(DomainError::InvalidReturnTo), "{bad:?}");
        }
    }

    #[test]
    fn limite_de_longitud() {
        let justo = format!("/{}", "a".repeat(RETURN_TO_MAX_LEN - 1));
        assert!(ReturnTo::parse(&justo).is_ok());
        let pasado = format!("/{}", "a".repeat(RETURN_TO_MAX_LEN));
        assert!(ReturnTo::parse(&pasado).is_err());
    }

    #[test]
    fn por_defecto_es_la_raiz() {
        assert_eq!(ReturnTo::parse_or_default(None).as_str(), "/");
        assert_eq!(ReturnTo::parse_or_default(Some("//evil.com")).as_str(), "/");
        assert_eq!(ReturnTo::parse_or_default(Some("/ok")).as_str(), "/ok");
    }

    fn host_de(url: &str) -> Option<String> {
        url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20_000))]

        #[test]
        fn aceptado_conserva_el_host(s in "\\PC{0,64}") {
            if let Ok(r) = ReturnTo::parse(&s) {
                let v = r.as_str();
                prop_assert!(v.starts_with('/'));
                prop_assert!(!v.starts_with("//") && !v.starts_with("/\\"));
                prop_assert_eq!(host_de(&format!("{ORIGIN}{v}")), Some("app.example.com".to_owned()));
            }
        }

        #[test]
        fn ascii_hostil_conserva_el_host(s in "/[ -~]{0,64}") {
            if let Ok(r) = ReturnTo::parse(&s) {
                let url = format!("{ORIGIN}{}", r.as_str());
                prop_assert_eq!(host_de(&url), Some("app.example.com".to_owned()));
                let parsed = url::Url::parse(&url).unwrap();
                prop_assert_eq!(parsed.username(), "");
                prop_assert_eq!(parsed.password(), None);
            }
        }

        #[test]
        fn fragmentos_peligrosos(prefix in "/[a-z]{0,8}", sep in prop::sample::select(vec!["//", "/\\", "@", "%2f", "%5C", "%0a", "%00", "%2e"]), suffix in "[a-z.]{0,12}") {
            let s = format!("{prefix}{sep}{suffix}");
            if let Ok(r) = ReturnTo::parse(&s) {
                let url = format!("{ORIGIN}{}", r.as_str());
                prop_assert_eq!(host_de(&url), Some("app.example.com".to_owned()));
            }
        }
    }
}
