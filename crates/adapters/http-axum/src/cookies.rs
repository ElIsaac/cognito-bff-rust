//! Cookies `__Host-` (§7.1): parser acotado y `Set-Cookie` con atributos fijos.

use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, header};

/// Nombre fijo de la cookie del login en curso.
pub const PENDING_COOKIE: &str = "__Host-bff_pending";

/// Tope de la suma de las cabeceras `Cookie`.
const COOKIE_HEADER_MAX: usize = 32 * 1024;
/// Tope del valor de la cookie buscada; mas alla no se intenta ni interpretarla.
const COOKIE_LOOKED_UP_MAX: usize = 8 * 1024;
/// Tope del valor valido (los IDs son 43 caracteres base64url).
const COOKIE_VALUE_MAX: usize = 128;

/// Resultado de buscar una cookie en las cabeceras `Cookie`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// No hay ningun par con ese nombre.
    Missing,
    /// Las cabeceras (o el valor buscado) son demasiado grandes para interpretarlas. No dice
    /// nada de la cookie: no hay motivo para borrarla.
    Unreadable,
    /// Esta, pero repetida, vacia, demasiado larga o fuera de base64url.
    Invalid,
    Value(String),
}

impl Lookup {
    /// El valor valido, o `None`: el caso de uso lo trata como "sin cookie".
    pub fn into_value(self) -> Option<String> {
        match self {
            Self::Value(v) => Some(v),
            Self::Missing | Self::Unreadable | Self::Invalid => None,
        }
    }
}

/// Busca la cookie `name` leyendo las cabeceras como bytes. Los pares de otras cookies, aunque
/// no sean ASCII, se saltan: solo el valor buscado y el total de las cabeceras tienen tope.
pub fn lookup(headers: &HeaderMap, name: &str) -> Lookup {
    let mut total = 0usize;
    let mut found: Option<&[u8]> = None;
    let mut repeated = false;
    for v in headers.get_all(header::COOKIE) {
        let raw = v.as_bytes();
        total = total.saturating_add(raw.len());
        if total > COOKIE_HEADER_MAX {
            return Lookup::Unreadable;
        }
        for pair in raw.split(|&b| b == b';') {
            let pair = pair.trim_ascii();
            let Some(eq) = pair.iter().position(|&b| b == b'=') else {
                continue;
            };
            if &pair[..eq] != name.as_bytes() {
                continue;
            }
            let val = &pair[eq + 1..];
            if val.len() > COOKIE_LOOKED_UP_MAX {
                return Lookup::Unreadable;
            }
            repeated |= found.is_some();
            found = Some(val);
        }
    }
    let Some(val) = found else {
        return Lookup::Missing;
    };
    let ok = !repeated
        && !val.is_empty()
        && val.len() <= COOKIE_VALUE_MAX
        && val
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_');
    if !ok {
        return Lookup::Invalid;
    }
    String::from_utf8(val.to_vec()).map_or(Lookup::Invalid, Lookup::Value)
}

/// Valor de la cookie `name`, o `None` si falta, esta repetida, es demasiado larga o tiene
/// caracteres fuera de base64url.
pub fn read(headers: &HeaderMap, name: &str) -> Option<String> {
    lookup(headers, name).into_value()
}

/// `Set-Cookie` con `Path=/; HttpOnly; Secure; SameSite=Lax`, sin `Domain`.
pub fn set(name: &str, value: &str, max_age: Duration) -> HeaderValue {
    build(name, value, max_age.as_secs())
}

/// `Set-Cookie` que borra la cookie.
pub fn clear(name: &str) -> HeaderValue {
    build(name, "", 0)
}

fn build(name: &str, value: &str, max_age: u64) -> HeaderValue {
    let s = format!("{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax");
    // Nombre validado en la config y valor base64url: siempre es una cabecera valida.
    HeaderValue::from_str(&s).unwrap_or_else(|_| HeaderValue::from_static("invalid=; Max-Age=0"))
}

/// `true` si `name` sirve como nombre de cookie `__Host-` (token RFC 6265).
pub fn valid_name(name: &str) -> bool {
    name.starts_with("__Host-")
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: &str = "__Host-bff_session";
    const ID: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde";

    fn h(values: &[&str]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for v in values {
            m.append(header::COOKIE, HeaderValue::from_str(v).unwrap());
        }
        m
    }

    fn hb(values: &[&[u8]]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for v in values {
            m.append(header::COOKIE, HeaderValue::from_bytes(v).unwrap());
        }
        m
    }

    #[test]
    fn salta_las_ajenas_ilegibles() {
        let mut raw = b"otra=caf\xe9; ".to_vec();
        raw.extend_from_slice(format!("{N}={ID}; ").as_bytes());
        raw.extend_from_slice(b"\xff\xfe=1");
        assert_eq!(read(&hb(&[&raw]), N).as_deref(), Some(ID));
        // Tambien en cabeceras distintas y con el nombre ajeno no ASCII.
        let propia = format!("{N}={ID}");
        assert_eq!(
            read(&hb(&[b"\xc3\xb1=\xc3\xa9", propia.as_bytes()]), N).as_deref(),
            Some(ID)
        );
        // Un valor propio no ASCII si es invalido.
        let mala = format!("{N}=\u{e9}");
        assert_eq!(lookup(&hb(&[mala.as_bytes()]), N), Lookup::Invalid);
    }

    #[test]
    fn topes_de_tamano() {
        // Mas de 8 KiB de cookies ajenas, bajo los 32 KiB: la sesion se lee.
        let ajenas = format!("a={}; b={}", "x".repeat(5000), "y".repeat(5000));
        assert_eq!(
            read(&h(&[&format!("{ajenas}; {N}={ID}")]), N).as_deref(),
            Some(ID)
        );
        assert_eq!(read(&h(&[&ajenas, &format!("{N}={ID}")]), N).as_deref(), Some(ID));
        // Sobre los 32 KiB en total: ilegible, no invalida.
        let relleno: Vec<String> = (0..9).map(|i| format!("c{i}={}", "x".repeat(4000))).collect();
        let enorme = format!("{}; {N}={ID}", relleno.join("; "));
        assert!(enorme.len() > COOKIE_HEADER_MAX);
        assert_eq!(lookup(&h(&[&enorme]), N), Lookup::Unreadable);
        let dos = format!("a={}", "x".repeat(20_000));
        assert_eq!(lookup(&h(&[&dos, &dos]), N), Lookup::Unreadable);
        // El valor buscado: >128 es invalido, >8 KiB es ilegible.
        let largo = |n: usize| format!("{N}={}", "a".repeat(n));
        assert_eq!(lookup(&h(&[&largo(129)]), N), Lookup::Invalid);
        assert_eq!(lookup(&h(&[&largo(8 * 1024)]), N), Lookup::Invalid);
        assert_eq!(lookup(&h(&[&largo(8 * 1024 + 1)]), N), Lookup::Unreadable);
    }

    #[test]
    fn estados_de_la_busqueda() {
        assert_eq!(lookup(&h(&[]), N), Lookup::Missing);
        assert_eq!(lookup(&h(&["a=1; b=2"]), N), Lookup::Missing);
        assert_eq!(lookup(&h(&[&format!("{N}=")]), N), Lookup::Invalid);
        assert_eq!(lookup(&h(&[&format!("{N}={ID}; {N}={ID}")]), N), Lookup::Invalid);
        assert_eq!(
            lookup(&h(&[&format!("{N}={ID}")]), N),
            Lookup::Value(ID.to_owned())
        );
    }

    #[test]
    fn lee_entre_varias() {
        assert_eq!(
            read(&h(&[&format!("a=1; {N}={ID}; b=2")]), N).as_deref(),
            Some(ID)
        );
        assert_eq!(read(&h(&["a=1", &format!("{N}={ID}")]), N).as_deref(), Some(ID));
    }

    #[test]
    fn ignora_lo_malformado() {
        assert_eq!(read(&h(&[]), N), None);
        assert_eq!(read(&h(&[&format!("{N}=")]), N), None);
        assert_eq!(read(&h(&[&format!("{N}=a.b")]), N), None);
        assert_eq!(read(&h(&[&format!("{N}=\"{ID}\"")]), N), None);
        assert_eq!(read(&h(&[&format!("{N}={}", "a".repeat(129))]), N), None);
        assert_eq!(read(&h(&[&format!("x={}", "a".repeat(9000))]), N), None);
        // Repetida: ambigua.
        assert_eq!(read(&h(&[&format!("{N}={ID}; {N}=otro")]), N), None);
        // Prefijo parecido no cuenta.
        assert_eq!(read(&h(&[&format!("{N}x={ID}")]), N), None);
    }

    #[test]
    fn set_cookie_con_atributos_fijos() {
        let v = set(N, ID, Duration::from_secs(60));
        assert_eq!(
            v.to_str().unwrap(),
            format!("{N}={ID}; Path=/; Max-Age=60; HttpOnly; Secure; SameSite=Lax")
        );
        assert!(
            clear(N)
                .to_str()
                .unwrap()
                .starts_with(&format!("{N}=; Path=/; Max-Age=0;"))
        );
    }

    #[test]
    fn nombres() {
        assert!(valid_name(N));
        assert!(!valid_name("bff_session"));
        assert!(!valid_name("__Host-a b"));
        assert!(!valid_name("__Host-a;b"));
    }
}
