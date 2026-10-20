//! Cookies `__Host-` (§7.1): parser acotado y `Set-Cookie` con atributos fijos.

use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, header};

/// Nombre fijo de la cookie del login en curso.
pub const PENDING_COOKIE: &str = "__Host-bff_pending";

/// Tope de la suma de las cabeceras `Cookie`.
const COOKIE_HEADER_MAX: usize = 8 * 1024;
/// Tope del valor (los IDs son 43 caracteres base64url).
const COOKIE_VALUE_MAX: usize = 128;

/// Valor de la cookie `name`, o `None` si falta, esta repetida, es demasiado larga o tiene
/// caracteres fuera de base64url. Un valor malformado se ignora: el caso de uso lo trata
/// como "sin cookie".
pub fn read(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut total = 0usize;
    let mut found: Option<&str> = None;
    for v in headers.get_all(header::COOKIE) {
        let raw = v.to_str().ok()?;
        total = total.saturating_add(raw.len());
        if total > COOKIE_HEADER_MAX {
            return None;
        }
        for pair in raw.split(';') {
            let Some((k, val)) = pair.trim().split_once('=') else {
                continue;
            };
            if k != name {
                continue;
            }
            if found.is_some() {
                return None;
            }
            found = Some(val);
        }
    }
    let val = found?;
    let ok = !val.is_empty()
        && val.len() <= COOKIE_VALUE_MAX
        && val
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    ok.then(|| val.to_owned())
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
