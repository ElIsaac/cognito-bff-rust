#![no_main]

use http_axum::fuzzing::cookie_value;
use libfuzzer_sys::fuzz_target;

const NAME: &str = "__Host-bff_session";
const VALUE_MAX: usize = 128;

/// Cuantas veces aparece `NAME` como par de una cabecera que `to_str` acepta (ASCII visible
/// y tabulador).
fn occurrences(headers: &[&[u8]]) -> usize {
    headers
        .iter()
        .filter(|h| h.iter().all(|&b| b == b'\t' || (0x20..=0x7E).contains(&b)))
        .filter_map(|h| std::str::from_utf8(h).ok())
        .flat_map(|h| h.split(';'))
        .filter(|pair| pair.trim().split_once('=').is_some_and(|(k, _)| k == NAME))
        .count()
}

fuzz_target!(|data: &[u8]| {
    // Cada linea es una cabecera `Cookie` distinta (un salto de linea no cabe en una).
    let headers: Vec<&[u8]> = data.split(|&b| b == b'\n').collect();
    let got = cookie_value(&headers, NAME);
    if let Some(v) = &got {
        assert!(!v.is_empty() && v.len() <= VALUE_MAX, "largo fuera de rango");
        assert!(
            v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "no es base64url: {v:?}"
        );
    }
    if occurrences(&headers) >= 2 {
        assert!(got.is_none(), "cookie repetida debe ser None");
    }
});
