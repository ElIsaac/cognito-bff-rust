//! Verificacion CSRF de la capa de aplicacion (plan 7.2).

use application::csrf::check;
use application::ports::{Header, Method};

use crate::common::{CSRF_HEADER, ORIGIN};

fn h(k: &str, v: &str) -> Header {
    (k.to_owned(), v.to_owned())
}

fn ok(method: Method, headers: &[Header]) -> bool {
    check(method, headers, ORIGIN, CSRF_HEADER)
}

/// CSRF clasico: un POST/PUT/PATCH/DELETE sin la cabecera personalizada (un formulario de
/// otro sitio no puede ponerla) se rechaza.
#[test]
fn metodos_inseguros_sin_cabecera_se_rechazan() {
    for m in [Method::Post, Method::Put, Method::Patch, Method::Delete] {
        assert!(!ok(m, &[]), "{m:?}");
        assert!(!ok(m, &[h("origin", ORIGIN)]), "{m:?}");
        assert!(ok(m, &[h(CSRF_HEADER, "XMLHttpRequest")]), "{m:?}");
    }
}

/// Peticion cross-site con la cabecera presente (p. ej. CORS mal configurado en otro
/// sitio): `Sec-Fetch-Site: cross-site` o `same-site` se rechaza.
#[test]
fn sec_fetch_site_ajeno_se_rechaza() {
    for v in ["cross-site", "same-site", ""] {
        let hs = [h(CSRF_HEADER, "1"), h("sec-fetch-site", v)];
        assert!(!ok(Method::Post, &hs), "{v:?}");
    }
    for v in ["same-origin", "none"] {
        let hs = [h(CSRF_HEADER, "1"), h("sec-fetch-site", v)];
        assert!(ok(Method::Post, &hs), "{v:?}");
    }
}

/// `Origin` ajeno, `null`, con prefijo igual o con barra final: se rechaza.
#[test]
fn origin_ajeno_se_rechaza() {
    for v in [
        "https://evil.com",
        "null",
        "https://app.example.com.evil.com",
        "http://app.example.com",
        "https://app.example.com/",
    ] {
        let hs = [h(CSRF_HEADER, "1"), h("origin", v)];
        assert!(!ok(Method::Delete, &hs), "{v}");
    }
    assert!(ok(Method::Delete, &[h(CSRF_HEADER, "1"), h("origin", ORIGIN)]));
}

/// Cabeceras repetidas son ambiguas (un proxy intermedio podria haber inyectado una): se
/// rechazan.
#[test]
fn cabeceras_repetidas_se_rechazan() {
    let hs = [h(CSRF_HEADER, "1"), h(CSRF_HEADER, "2")];
    assert!(!ok(Method::Post, &hs));
    let hs = [
        h(CSRF_HEADER, "1"),
        h("origin", ORIGIN),
        h("origin", "https://evil.com"),
    ];
    assert!(!ok(Method::Post, &hs));
}

/// Los metodos seguros no exigen nada (no cambian estado).
#[test]
fn metodos_seguros_siempre_pasan() {
    for m in [Method::Get, Method::Head, Method::Options] {
        assert!(ok(m, &[]));
    }
}
