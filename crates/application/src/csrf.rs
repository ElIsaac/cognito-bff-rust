//! Verificacion CSRF para metodos que cambian estado (§7.2).

use crate::ports::{Header, Method};

enum Lookup<'a> {
    Absent,
    One(&'a str),
    /// Repetida: un valor ambiguo no se acepta.
    Many,
}

fn lookup<'a>(headers: &'a [Header], name: &str) -> Lookup<'a> {
    let mut found = headers.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str());
    match (found.next(), found.next()) {
        (None, _) => Lookup::Absent,
        (Some(v), None) => Lookup::One(v),
        (Some(_), Some(_)) => Lookup::Many,
    }
}

/// `true` si la peticion pasa:
/// 1. La cabecera `csrf_header` esta presente una sola vez (su valor no importa).
/// 2. Si llega `Sec-Fetch-Site`, es `same-origin` o `none`.
/// 3. Si llega `Origin`, es igual a `public_origin`.
///
/// Los metodos seguros siempre pasan.
pub fn check(method: Method, headers: &[Header], public_origin: &str, csrf_header: &str) -> bool {
    if !method.is_unsafe() {
        return true;
    }
    if !matches!(lookup(headers, csrf_header), Lookup::One(_)) {
        return false;
    }
    let fetch_site_ok = match lookup(headers, "sec-fetch-site") {
        Lookup::Absent => true,
        Lookup::One(v) => v == "same-origin" || v == "none",
        Lookup::Many => false,
    };
    let origin_ok = match lookup(headers, "origin") {
        Lookup::Absent => true,
        Lookup::One(v) => v == public_origin,
        Lookup::Many => false,
    };
    fetch_site_ok && origin_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://app.example.com";
    const H: &str = "x-requested-with";

    fn h(pairs: &[(&str, &str)]) -> Vec<Header> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn metodos_seguros_pasan() {
        assert!(check(Method::Get, &[], ORIGIN, H));
        assert!(check(Method::Head, &[], ORIGIN, H));
        assert!(check(Method::Options, &[], ORIGIN, H));
    }

    #[test]
    fn sin_cabecera_falla() {
        for m in [Method::Post, Method::Put, Method::Patch, Method::Delete] {
            assert!(!check(m, &h(&[("origin", ORIGIN)]), ORIGIN, H));
        }
    }

    #[test]
    fn casos() {
        assert!(check(Method::Post, &h(&[(H, "fetch")]), ORIGIN, H));
        assert!(check(
            Method::Post,
            &h(&[(H, ""), ("sec-fetch-site", "same-origin"), ("origin", ORIGIN)]),
            ORIGIN,
            H
        ));
        assert!(check(
            Method::Post,
            &h(&[(H, "x"), ("sec-fetch-site", "none")]),
            ORIGIN,
            H
        ));
        assert!(!check(
            Method::Post,
            &h(&[(H, "x"), ("sec-fetch-site", "cross-site")]),
            ORIGIN,
            H
        ));
        assert!(!check(
            Method::Post,
            &h(&[(H, "x"), ("sec-fetch-site", "same-site")]),
            ORIGIN,
            H
        ));
        assert!(!check(
            Method::Post,
            &h(&[(H, "x"), ("origin", "https://evil.com")]),
            ORIGIN,
            H
        ));
        assert!(!check(
            Method::Post,
            &h(&[(H, "x"), ("origin", "https://app.example.com.evil.com")]),
            ORIGIN,
            H
        ));
        assert!(!check(
            Method::Post,
            &h(&[(H, "x"), ("origin", "null")]),
            ORIGIN,
            H
        ));
        assert!(!check(
            Method::Post,
            &h(&[(H, "x"), ("origin", ORIGIN), ("origin", "https://evil.com")]),
            ORIGIN,
            H
        ));
        assert!(!check(Method::Post, &h(&[(H, "x"), (H, "y")]), ORIGIN, H));
    }
}
