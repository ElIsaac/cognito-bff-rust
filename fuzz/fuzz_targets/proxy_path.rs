#![no_main]

use domain::ProxyPath;
use libfuzzer_sys::fuzz_target;

/// Una sola decodificacion de `%XX`; el dominio ya garantiza que cada `%` va seguido de
/// dos hexadecimales, pero aqui no se asume.
fn decode_once(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).expect("ascii");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(p) = ProxyPath::parse(s) else {
        return;
    };
    let v = p.as_str();
    assert!(!v.starts_with('/'), "empieza por /: {v:?}");
    for seg in v.split('/') {
        let decoded = decode_once(seg);
        assert!(decoded != b"." && decoded != b"..", "segmento punto: {v:?}");
        assert!(
            !decoded.iter().any(|b| matches!(b, b'/' | b'\\' | 0)),
            "separador o NUL decodificado en un segmento: {v:?}"
        );
    }
});
