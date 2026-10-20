#![no_main]

use domain::ReturnTo;
use libfuzzer_sys::fuzz_target;
use url::Url;

const ORIGIN_HOST: &str = "app.example.com";

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(rt) = ReturnTo::parse(s) else {
        return;
    };
    let v = rt.as_str();
    assert!(v.starts_with('/'), "no empieza por /: {v:?}");
    assert!(!v.starts_with("//"), "empieza por //: {v:?}");
    assert!(!v.starts_with("/\\"), "empieza por /\\: {v:?}");
    let base = Url::parse("https://app.example.com").expect("base valida");
    let joined = base.join(v).expect("un ReturnTo aceptado siempre se une");
    assert_eq!(joined.host_str(), Some(ORIGIN_HOST), "cambio de host: {v:?}");
    assert_eq!(joined.scheme(), "https", "cambio de esquema: {v:?}");
});
