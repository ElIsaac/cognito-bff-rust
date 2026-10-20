#![no_main]

use http_axum::fuzzing::single_query_value;
use libfuzzer_sys::fuzz_target;

const QUERY_MAX: usize = 8 * 1024;

fuzz_target!(|data: &[u8]| {
    let Ok(q) = std::str::from_utf8(data) else {
        return;
    };
    for key in ["code", "state", "error", "returnTo"] {
        let got = single_query_value(Some(q), key);
        if q.len() > QUERY_MAX {
            assert!(got.is_none(), "query demasiado larga debe ser None");
        }
        // Con la clave repetida delante el resultado es siempre None.
        let repeated = format!("{key}=a&{key}=b&{q}");
        if repeated.len() <= QUERY_MAX {
            assert!(
                single_query_value(Some(&repeated), key).is_none(),
                "clave repetida debe ser None"
            );
        }
    }
    assert!(single_query_value(None, "code").is_none());
});
