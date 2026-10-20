//! Ataques contra la validacion del ID token: todos deben terminar en `TokenRejected`.

use aws_lc_rs::hmac;
use serde_json::{Value, json};

use crate::support::{Env, KID_A, b64, key_a, key_attacker, now, other_nonce};

/// Firma con la llave valida de la A (RS256, `kid` de la A).
fn firmado(env_claims: &Value) -> String {
    key_a().token(env_claims)
}

/// Token de control: sin tocar nada, el mismo constructor produce un token aceptado. Si
/// este test falla, los rechazos de abajo no demuestran nada.
#[tokio::test]
async fn control_el_token_sin_alterar_se_acepta() {
    let env = Env::start().await;
    assert!(env.exchange(&firmado(&env.claims())).await.is_ok());
}

/// Firma falsificada: un atacante firma con su propia llave RSA pero reutiliza el `kid`
/// legitimo del JWKS.
#[tokio::test]
async fn firma_de_otra_llave_con_el_mismo_kid() {
    let env = Env::start().await;
    let forged = key_attacker().sign(
        &json!({"alg": "RS256", "typ": "JWT", "kid": KID_A}),
        &env.claims(),
    );
    env.assert_rejected(&forged).await;
}

/// Firma alterada: se cambia un byte de la firma de un token valido.
#[tokio::test]
async fn firma_corrupta() {
    let env = Env::start().await;
    let t = firmado(&env.claims());
    let (head, sig) = t.rsplit_once('.').unwrap();
    let mut sig = sig.to_owned();
    let flipped = if sig.starts_with('A') { 'B' } else { 'A' };
    sig.replace_range(0..1, &flipped.to_string());
    env.assert_rejected(&format!("{head}.{sig}")).await;
}

/// Payload alterado tras firmar (p. ej. cambiar `sub` a otro usuario) con la firma
/// original.
#[tokio::test]
async fn payload_modificado_con_la_firma_original() {
    let env = Env::start().await;
    let t = firmado(&env.claims());
    let parts: Vec<&str> = t.split('.').collect();
    let mut claims = env.claims();
    claims["sub"] = json!("sub-del-administrador");
    let tampered = format!("{}.{}.{}", parts[0], b64(claims.to_string()), parts[2]);
    env.assert_rejected(&tampered).await;
}

/// `alg: none` (CVE clasico): JWT sin firma construido a mano; se prueba con firma vacia,
/// sin el tercer segmento y con las variantes de mayusculas del `alg`.
#[tokio::test]
async fn alg_none() {
    let env = Env::start().await;
    for alg in ["none", "None", "NONE"] {
        let header = json!({"alg": alg, "typ": "JWT", "kid": KID_A});
        let body = format!("{}.{}", b64(header.to_string()), b64(env.claims().to_string()));
        env.assert_rejected(&format!("{body}.")).await;
        env.assert_rejected(&body).await;
    }
}

/// Confusion de algoritmo: `alg: HS256` firmado con HMAC usando la llave publica (DER
/// PKCS#1, su `n` en base64url y un PEM) como secreto; un validador que confie en el `alg`
/// del header lo aceptaria.
#[tokio::test]
async fn alg_hs256_firmado_con_la_llave_publica() {
    let env = Env::start().await;
    let pem = format!(
        "-----BEGIN RSA PUBLIC KEY-----\n{}\n-----END RSA PUBLIC KEY-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key_a().public_der)
    );
    let secrets: Vec<Vec<u8>> = vec![
        key_a().public_der.clone(),
        key_a().n.clone().into_bytes(),
        pem.into_bytes(),
    ];
    for alg in ["HS256", "HS384", "HS512"] {
        let algorithm = match alg {
            "HS256" => hmac::HMAC_SHA256,
            "HS384" => hmac::HMAC_SHA384,
            _ => hmac::HMAC_SHA512,
        };
        for secret in &secrets {
            let header = json!({"alg": alg, "typ": "JWT", "kid": KID_A});
            let input = format!("{}.{}", b64(header.to_string()), b64(env.claims().to_string()));
            let tag = hmac::sign(&hmac::Key::new(algorithm, secret), input.as_bytes());
            env.assert_rejected(&format!("{input}.{}", b64(tag.as_ref())))
                .await;
        }
    }
}

/// Otros algoritmos asimetricos (`RS384`, `ES256`, `PS256`) tampoco se aceptan aunque el
/// header sea coherente: el algoritmo esta fijado a RS256.
#[tokio::test]
async fn algoritmos_distintos_de_rs256() {
    let env = Env::start().await;
    for alg in ["RS384", "RS512", "ES256", "PS256", "EdDSA"] {
        let header = json!({"alg": alg, "typ": "JWT", "kid": KID_A});
        let t = key_a().sign(&header, &env.claims());
        env.assert_rejected(&t).await;
    }
}

/// Token emitido por otro pool/emisor (mismo firmante, `iss` distinto): un token de
/// otro entorno no sirve aqui.
#[tokio::test]
async fn issuer_distinto() {
    let env = Env::start().await;
    for iss in [
        "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_OTRO",
        &format!("{}/", env.cfg.issuer),
        "",
    ] {
        let mut c = env.claims();
        c["iss"] = json!(iss);
        env.assert_rejected(&firmado(&c)).await;
    }
    let mut c = env.claims();
    c.as_object_mut().unwrap().remove("iss");
    env.assert_rejected(&firmado(&c)).await;
}

/// Token emitido para otra aplicacion del mismo pool (`aud` distinto) o sin `aud`:
/// confused deputy.
#[tokio::test]
async fn audience_distinta() {
    let env = Env::start().await;
    for aud in [json!("otro-client-id"), json!(["otro-client-id"]), json!("")] {
        let mut c = env.claims();
        c["aud"] = aud;
        env.assert_rejected(&firmado(&c)).await;
    }
    let mut c = env.claims();
    c.as_object_mut().unwrap().remove("aud");
    env.assert_rejected(&firmado(&c)).await;
}

/// Token vencido: `exp` pasado por mas de la tolerancia de reloj (60 s) se rechaza...
#[tokio::test]
async fn exp_vencido_mas_alla_del_leeway() {
    let env = Env::start().await;
    let mut c = env.claims();
    c["iat"] = json!(now() - 7200);
    c["exp"] = json!(now() - 120);
    env.assert_rejected(&firmado(&c)).await;
}

/// ... y uno vencido hace menos de 60 s (desfase de reloj normal) se acepta.
#[tokio::test]
async fn exp_vencido_dentro_del_leeway_se_acepta() {
    let env = Env::start().await;
    let mut c = env.claims();
    c["iat"] = json!(now() - 3600);
    c["exp"] = json!(now() - 30);
    assert!(env.exchange(&firmado(&c)).await.is_ok());
}

/// Sin `exp` el token no caducaria nunca: se exige.
#[tokio::test]
async fn exp_ausente() {
    let env = Env::start().await;
    let mut c = env.claims();
    c.as_object_mut().unwrap().remove("exp");
    env.assert_rejected(&firmado(&c)).await;
}

/// `iat` en el futuro mas alla de 60 s (token "adelantado" o reloj del emisor
/// manipulado) se rechaza...
#[tokio::test]
async fn iat_en_el_futuro() {
    let env = Env::start().await;
    let mut c = env.claims();
    c["iat"] = json!(now() + 300);
    env.assert_rejected(&firmado(&c)).await;
}

/// ... y un `iat` adelantado 30 s (dentro de la tolerancia) se acepta.
#[tokio::test]
async fn iat_dentro_del_leeway_se_acepta() {
    let env = Env::start().await;
    let mut c = env.claims();
    c["iat"] = json!(now() + 30);
    assert!(env.exchange(&firmado(&c)).await.is_ok());
}

/// `iat` ausente: el claim es obligatorio.
#[tokio::test]
async fn iat_ausente() {
    let env = Env::start().await;
    let mut c = env.claims();
    c.as_object_mut().unwrap().remove("iat");
    env.assert_rejected(&firmado(&c)).await;
}

/// `nbf` en el futuro: el token aun no es valido.
#[tokio::test]
async fn nbf_en_el_futuro() {
    let env = Env::start().await;
    let mut c = env.claims();
    c["nbf"] = json!(now() + 600);
    env.assert_rejected(&firmado(&c)).await;
}

/// Sustitucion de token: un access token (`token_use = access`) firmado por el mismo
/// pool no se acepta como ID token.
#[tokio::test]
async fn token_use_access() {
    let env = Env::start().await;
    for tu in [json!("access"), json!(""), json!("ID")] {
        let mut c = env.claims();
        c["token_use"] = tu;
        env.assert_rejected(&firmado(&c)).await;
    }
    let mut c = env.claims();
    c.as_object_mut().unwrap().remove("token_use");
    env.assert_rejected(&firmado(&c)).await;
}

/// Replay/inyeccion de login: el ID token lleva el nonce de otro login (otra sesion de
/// navegador).
#[tokio::test]
async fn nonce_distinto() {
    let env = Env::start().await;
    let mut c = env.claims();
    c["nonce"] = json!(other_nonce().expose_secret());
    env.assert_rejected(&firmado(&c)).await;
    for raro in [json!(""), json!(1), json!("prefijo")] {
        c["nonce"] = raro;
        env.assert_rejected(&firmado(&c)).await;
    }
}

/// Un ID token sin `nonce` en un canje de code (donde se espera) se rechaza: quitar el
/// claim no puede saltarse la comprobacion.
#[tokio::test]
async fn nonce_ausente_cuando_se_espera() {
    let env = Env::start().await;
    let mut c = env.claims();
    c.as_object_mut().unwrap().remove("nonce");
    env.assert_rejected(&firmado(&c)).await;
}

/// Header sin `kid`: no se puede elegir llave, se rechaza (no se prueba "todas las
/// llaves").
#[tokio::test]
async fn kid_ausente() {
    let env = Env::start().await;
    let t = key_a().sign(&json!({"alg": "RS256", "typ": "JWT"}), &env.claims());
    env.assert_rejected(&t).await;
}

/// `kid` que no esta en el JWKS (ni aparece tras refrescarlo) se rechaza.
#[tokio::test]
async fn kid_desconocido() {
    let env = Env::start().await;
    let t = key_a().sign(
        &json!({"alg": "RS256", "typ": "JWT", "kid": "inventado"}),
        &env.claims(),
    );
    env.assert_rejected(&t).await;
    for raro in [json!(""), json!(5), json!(null), json!("../../etc/passwd")] {
        let t = key_a().sign(&json!({"alg": "RS256", "typ": "JWT", "kid": raro}), &env.claims());
        env.assert_rejected(&t).await;
    }
}

/// Header con `jku`/`jwk`/`x5u` embebidos que apuntan a una llave del atacante: se
/// ignoran y se valida solo contra el JWKS del emisor configurado.
#[tokio::test]
async fn jwk_embebido_en_el_header_se_ignora() {
    let env = Env::start().await;
    let header = json!({
        "alg": "RS256", "typ": "JWT", "kid": KID_A,
        "jwk": key_attacker().jwk(),
        "jku": "http://127.0.0.1:1/atacante.json",
    });
    env.assert_rejected(&key_attacker().sign(&header, &env.claims()))
        .await;
}

/// `sub` vacio (o con caracteres no admitidos) no produce una identidad valida.
#[tokio::test]
async fn sub_vacio_o_invalido() {
    let env = Env::start().await;
    for sub in ["", "con espacio", "x\ny"] {
        let mut c = env.claims();
        c["sub"] = json!(sub);
        env.assert_rejected(&firmado(&c)).await;
    }
    let mut c = env.claims();
    c.as_object_mut().unwrap().remove("sub");
    env.assert_rejected(&firmado(&c)).await;
}

/// Entradas basura en lugar del ID token: nunca provocan panico ni otro error que
/// `TokenRejected`.
#[tokio::test]
async fn token_malformado() {
    let env = Env::start().await;
    let basura = [
        "",
        "no-es-un-jwt",
        "a.b",
        "a.b.c",
        "..",
        "e30.e30.e30",
        "eyJhbGciOiJSUzI1NiJ9.e30.",
        "\u{0}\u{0}.\u{0}.\u{0}",
        "💥.💥.💥",
        &"a".repeat(100_000),
    ];
    for t in basura {
        env.assert_rejected(t).await;
    }
    let valido = firmado(&env.claims());
    env.assert_rejected(&valido[..valido.len() / 2]).await;
    env.assert_rejected(&format!("{valido}.extra")).await;
}

/// Claims que no son JSON de objeto o de tipo equivocado (`groups` no es lista,
/// `exp` cadena) se rechazan en lugar de aceptarse parcialmente.
#[tokio::test]
async fn claims_con_tipos_equivocados() {
    let env = Env::start().await;
    let mut c = env.claims();
    c["cognito:groups"] = json!("admins");
    env.assert_rejected(&firmado(&c)).await;
    let mut c = env.claims();
    c["exp"] = json!("manana");
    env.assert_rejected(&firmado(&c)).await;
    let mut c = env.claims();
    c["iat"] = json!(-5);
    env.assert_rejected(&firmado(&c)).await;
}
