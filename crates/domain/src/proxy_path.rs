use crate::DomainError;

/// Longitud maxima de la ruta reenviada al upstream.
pub const PROXY_PATH_MAX_LEN: usize = 2048;

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Ruta relativa que sigue a `/api/` y se concatena a `UPSTREAM_BASE_URL`.
///
/// Reglas (todo lo demas se rechaza con `400`):
/// 1. ASCII visible (0x21–0x7E), sin `\`, `?` ni `#`, longitud ≤ `PROXY_PATH_MAX_LEN`.
/// 2. No empieza por `/`; ningun segmento es `.` ni `..`; no hay segmentos vacios salvo
///    una `/` final.
/// 3. Todo `%` va seguido de dos hexadecimales y no codifica `/`, `\`, `.`, `%` ni un
///    control.
///
/// Asi el destino es siempre `UPSTREAM_BASE_URL + "/" + ruta` y nada del cliente decide el
/// host ni escapa del prefijo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyPath(String);

impl ProxyPath {
    /// # Errors
    /// `DomainError::InvalidProxyPath` si incumple alguna regla.
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        let err = Err(DomainError::InvalidProxyPath);
        let b = s.as_bytes();
        if b.len() > PROXY_PATH_MAX_LEN {
            return err;
        }
        if !b
            .iter()
            .all(|&c| (0x21..=0x7E).contains(&c) && !matches!(c, b'\\' | b'?' | b'#'))
        {
            return err;
        }
        if b.first() == Some(&b'/') {
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
                let v = hi << 4 | lo;
                if matches!(v, b'/' | b'\\' | b'.' | b'%') || v < 0x20 || v == 0x7F {
                    return err;
                }
                i += 3;
            } else {
                i += 1;
            }
        }

        let segments: Vec<&str> = s.split('/').collect();
        let last = segments.len() - 1;
        for (idx, seg) in segments.iter().enumerate() {
            if *seg == "." || *seg == ".." {
                return err;
            }
            if seg.is_empty() && idx != last && !s.is_empty() {
                return err;
            }
        }

        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acepta_rutas_normales() {
        for ok in [
            "",
            "v1/admin/ventas",
            "v1/admin/ventas/",
            "v1/a-b_c~d.json",
            "v1/%E2%9C%93",
            "v1/a:b@c",
        ] {
            assert!(ProxyPath::parse(ok).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn rechaza_escapes_del_prefijo() {
        for bad in [
            "..",
            "../auth/me",
            "v1/../../auth",
            "v1/./x",
            ".",
            "%2e%2e/",
            "..%2f",
            "%2e%2e%2fauth",
            "v1%2f..",
            "v1%5c..",
            "/v1",
            "//evil.com/x",
            "https://evil",
            "v1//x",
            "v1\\x",
            "v1/x?y=1",
            "v1/x#f",
            "v1/x y",
            "v1/%00",
            "v1/%0d%0a",
            "v1/%252e%252e",
            "v1/%",
            "v1/%G0",
            "v1/caf\u{e9}",
        ] {
            assert_eq!(
                ProxyPath::parse(bad),
                Err(DomainError::InvalidProxyPath),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn https_evil_no_cambia_host() {
        // `https:` es un segmento valido pero `//` no: el host nunca sale del cliente.
        assert!(ProxyPath::parse("https://evil").is_err());
        assert!(ProxyPath::parse("https:/evil").is_ok());
    }

    #[test]
    fn limite_de_longitud() {
        assert!(ProxyPath::parse(&"a".repeat(PROXY_PATH_MAX_LEN)).is_ok());
        assert!(ProxyPath::parse(&"a".repeat(PROXY_PATH_MAX_LEN + 1)).is_err());
    }
}
