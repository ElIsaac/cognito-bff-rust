//! Listas blancas de cabeceras del proxy (§6.5). Los nombres se normalizan a minusculas
//! aqui mismo, aunque el contrato de los puertos ya lo exija (defensa en profundidad).

use crate::ports::Header;

/// Cabeceras del cliente que pueden llegar al upstream. `Authorization` la pone el BFF.
const REQUEST_ALLOW: &[&str] = &[
    "content-type",
    "content-length",
    "accept",
    "accept-language",
    "accept-encoding",
    "if-none-match",
    "if-modified-since",
    "x-request-id",
    "traceparent",
    "tracestate",
];

/// Cabeceras de respuesta del upstream que nunca llegan al navegador.
const RESPONSE_DENY: &[&str] = &[
    "set-cookie",
    "set-cookie2",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "content-length",
    "strict-transport-security",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-expose-headers",
];

/// Hay valores con controles (CR/LF) que no deben reenviarse.
fn clean_value(v: &str) -> bool {
    !v.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7F)
}

/// Filtra por lista blanca. `content-length` se descarta tambien: lo recalcula el cliente
/// HTTP a partir del body.
pub fn request_allowlist(headers: &[Header]) -> Vec<Header> {
    headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .filter(|(k, v)| k != "content-length" && REQUEST_ALLOW.contains(&k.as_str()) && clean_value(v))
        .map(|(k, v)| (k, v.clone()))
        .collect()
}

/// Quita del upstream lo que no debe llegar al navegador.
pub fn response_filter(headers: &[Header]) -> Vec<Header> {
    headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .filter(|(k, v)| !RESPONSE_DENY.contains(&k.as_str()) && clean_value(v))
        .map(|(k, v)| (k, v.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<Header> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn peticion_solo_lista_blanca() {
        let entrada = h(&[
            ("cookie", "__Host-bff_session=x"),
            ("host", "evil.com"),
            ("x-forwarded-host", "evil.com"),
            ("x-forwarded-for", "1.2.3.4"),
            ("authorization", "Bearer robado"),
            ("x-origin-verify", "secreto"),
            ("connection", "close"),
            ("transfer-encoding", "chunked"),
            ("content-length", "10"),
            ("content-type", "application/json"),
            ("accept", "a\r\nx-inyectada: 1"),
            ("traceparent", "00-abc-def-01"),
        ]);
        let salida = request_allowlist(&entrada);
        assert_eq!(
            salida,
            h(&[
                ("content-type", "application/json"),
                ("traceparent", "00-abc-def-01")
            ])
        );
    }

    #[test]
    fn respuesta_sin_set_cookie_ni_hop_by_hop() {
        let entrada = h(&[
            ("set-cookie", "a=b"),
            ("connection", "keep-alive"),
            ("content-type", "application/json"),
            ("etag", "\"1\""),
            ("access-control-allow-origin", "*"),
        ]);
        assert_eq!(
            response_filter(&entrada),
            h(&[("content-type", "application/json"), ("etag", "\"1\"")])
        );
    }
}
