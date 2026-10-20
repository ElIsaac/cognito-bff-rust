//! Puertas de entrada para `fuzz/` (feature `fuzzing`). No forma parte de la API publica.

use axum::http::{HeaderMap, HeaderValue, header};

/// Lee la cookie `name` de las cabeceras `Cookie` crudas dadas. Los valores que no son una
/// cabecera HTTP valida se descartan, como haria el servidor antes de llegar al parser.
pub fn cookie_value(raw_headers: &[&[u8]], name: &str) -> Option<String> {
    let mut map = HeaderMap::new();
    for raw in raw_headers {
        if let Ok(v) = HeaderValue::from_bytes(raw) {
            map.append(header::COOKIE, v);
        }
    }
    crate::cookies::read(&map, name)
}

/// Valor unico de `key` en la query del login y del callback.
pub fn single_query_value(query: Option<&str>, key: &str) -> Option<String> {
    crate::routes::auth::single(query, key)
}
