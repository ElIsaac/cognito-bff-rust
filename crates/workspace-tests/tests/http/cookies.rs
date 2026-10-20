//! Cookies `__Host-` (§7.1): atributos fijos, fijacion de sesion y cookies hostiles.

use axum::http::StatusCode;

use crate::support::{Env, PENDING_COOKIE, Req, Resp, SESSION_COOKIE, assert_error};

/// Una `Set-Cookie` del BFF debe llevar nombre `__Host-`, `HttpOnly`, `Secure`,
/// `SameSite=Lax`, `Path=/` y ningun `Domain`.
fn assert_cookie_segura(linea: &str) {
    let mut partes = linea.split("; ");
    let (nombre, _valor) = partes.next().unwrap().split_once('=').unwrap();
    assert!(nombre.starts_with("__Host-"), "nombre sin __Host-: {linea}");
    let atributos: Vec<&str> = partes.collect();
    for requerido in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
        assert!(atributos.contains(&requerido), "falta {requerido}: {linea}");
    }
    assert!(
        atributos
            .iter()
            .all(|a| !a.to_ascii_lowercase().starts_with("domain")),
        "lleva Domain: {linea}"
    );
    assert!(
        atributos.iter().any(|a| a.starts_with("Max-Age=")),
        "sin Max-Age: {linea}"
    );
}

fn assert_todas_seguras(resp: &Resp, esperadas: usize) {
    let cookies = resp.set_cookies();
    assert_eq!(cookies.len(), esperadas, "{cookies:?}");
    for c in &cookies {
        assert_cookie_segura(c);
    }
}

/// Cookie de login en curso sin atributos de seguridad: se podria robar por JS o enviar
/// por HTTP plano.
#[tokio::test(start_paused = true)]
async fn cookie_pending_del_login_lleva_atributos_fijos() {
    let env = Env::new();
    let ini = env.iniciar(None).await;
    assert_todas_seguras(&ini.resp, 1);
    let c = &ini.resp.set_cookies()[0];
    assert!(c.starts_with(&format!("{PENDING_COOKIE}=")), "{c}");
    assert!(
        c.contains("Max-Age=600"),
        "el pending dura lo que la politica: {c}"
    );
}

/// Cookie de sesion del callback exitoso y borrado de la pending: ambas con atributos fijos.
#[tokio::test(start_paused = true)]
async fn cookies_del_callback_exitoso_llevan_atributos_fijos() {
    let env = Env::new();
    let s = env.login(None).await;
    assert_todas_seguras(&s.callback, 2);
    assert!(s.callback.cookie_fijada(SESSION_COOKIE).is_some());
    assert!(s.callback.borra_cookie(PENDING_COOKIE));
}

/// Callback fallido: la cookie que borra la pending tambien lleva atributos fijos (un
/// borrado sin `Secure`/`Path=/` no borra una cookie `__Host-`).
#[tokio::test(start_paused = true)]
async fn cookie_del_callback_fallido_lleva_atributos_fijos() {
    let env = Env::new();
    let r = env.send(Req::get("/auth/callback?code=x&state=y")).await;
    assert_todas_seguras(&r, 1);
}

/// Logout: el borrado de la sesion lleva atributos fijos y vacia el valor.
#[tokio::test(start_paused = true)]
async fn cookie_del_logout_lleva_atributos_fijos() {
    let env = Env::new();
    let id = env.sesion().await;
    let r = env.send(Req::post("/auth/logout").csrf().sesion(&id)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_todas_seguras(&r, 1);
    assert!(r.borra_cookie(SESSION_COOKIE), "{:?}", r.set_cookies());
}

/// El 401 borra la cookie de sesion con los mismos atributos.
#[tokio::test(start_paused = true)]
async fn cookie_del_401_lleva_atributos_fijos() {
    let env = Env::new();
    let r = env.send(Req::get("/auth/me")).await;
    assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    assert_todas_seguras(&r, 1);
    assert!(r.borra_cookie(SESSION_COOKIE));
}

/// El valor de la cookie de sesion no se parece al de la pending ni al hash guardado: es el
/// id de 43 caracteres base64url y el almacen solo guarda su hash.
#[tokio::test(start_paused = true)]
async fn cookie_de_sesion_es_un_id_opaco_de_43_caracteres() {
    let env = Env::new();
    let id = env.sesion().await;
    assert_eq!(id.len(), 43);
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    assert!(
        env.ports
            .sessions()
            .snapshot(&crate::support::hash_of(&id))
            .is_some()
    );
}

/// Fijacion de sesion: un atacante planta una sesion; cuando la victima completa su login
/// con esa cookie, el id cambia y la sesion vieja se elimina del almacen.
#[tokio::test(start_paused = true)]
async fn fijacion_de_sesion_id_nuevo_y_la_vieja_se_borra() {
    let env = Env::new();
    let vieja = env.sesion().await;
    assert_eq!(env.ports.sessions().len(), 1);

    let ini = env.iniciar(None).await;
    let code = env.emitir_code(&ini);
    let uri = format!("/auth/callback?code={code}&state={}", ini.state);
    let r = env
        .send(Req::get(&uri).cookie(PENDING_COOKIE, &ini.pending).sesion(&vieja))
        .await;
    let nueva = r.cookie_fijada(SESSION_COOKIE).expect("sesion nueva");

    assert_ne!(nueva, vieja);
    assert!(
        env.ports
            .sessions()
            .snapshot(&crate::support::hash_of(&vieja))
            .is_none()
    );
    assert!(
        env.ports
            .sessions()
            .snapshot(&crate::support::hash_of(&nueva))
            .is_some()
    );
    assert_eq!(env.ports.sessions().len(), 1);
    let r = env.send(Req::get("/auth/me").sesion(&vieja)).await;
    assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
}

/// Un id plantado que ni siquiera existe en el almacen nunca se adopta: la sesion es nueva.
#[tokio::test(start_paused = true)]
async fn fijacion_con_id_plantado_inexistente_no_se_adopta() {
    let env = Env::new();
    let plantada = "A".repeat(43);
    let ini = env.iniciar(None).await;
    let code = env.emitir_code(&ini);
    let uri = format!("/auth/callback?code={code}&state={}", ini.state);
    let r = env
        .send(
            Req::get(&uri)
                .cookie(PENDING_COOKIE, &ini.pending)
                .sesion(&plantada),
        )
        .await;
    let nueva = r.cookie_fijada(SESSION_COOKIE).unwrap();
    assert_ne!(nueva, plantada);
    assert!(
        env.ports
            .sessions()
            .snapshot(&crate::support::hash_of(&plantada))
            .is_none()
    );
}

/// Cada login produce un id de sesion distinto (sin ids predecibles ni reutilizados).
#[tokio::test(start_paused = true)]
async fn cada_login_tiene_un_session_id_nuevo() {
    let env = Env::new();
    let a = env.sesion().await;
    let b = env.sesion().await;
    let c = env.sesion().await;
    assert!(a != b && b != c && a != c);
    assert_eq!(env.ports.sessions().len(), 3);
}

/// Cookies de sesion hostiles: alteradas, truncadas, fuera del charset, repetidas o
/// desconocidas dan 401 y el 401 borra la cookie. La sesion valida no se ve afectada.
#[tokio::test(start_paused = true)]
async fn cookies_hostiles_dan_401_y_se_borran() {
    let env = Env::new();
    let id = env.sesion().await;
    let cambiada = format!("{}{}", if id.starts_with('A') { 'B' } else { 'A' }, &id[1..]);
    let truncada = &id[..38];
    let desconocida = "A".repeat(43);
    let casos: Vec<(&str, Vec<String>)> = vec![
        ("alterada", vec![format!("{SESSION_COOKIE}={cambiada}")]),
        ("truncada", vec![format!("{SESSION_COOKIE}={truncada}")]),
        ("alargada", vec![format!("{SESSION_COOKIE}={id}AAAA")]),
        ("punto", vec![format!("{SESSION_COOKIE}={id}.")]),
        ("signo", vec![format!("{SESSION_COOKIE}={}!", &id[..42])]),
        ("entre comillas", vec![format!("{SESSION_COOKIE}=\"{id}\"")]),
        ("porcentaje", vec![format!("{SESSION_COOKIE}=%41{}", &id[1..])]),
        ("relleno base64", vec![format!("{SESSION_COOKIE}={id}=")]),
        ("vacia", vec![format!("{SESSION_COOKIE}=")]),
        ("enorme", vec![format!("{SESSION_COOKIE}={}", "a".repeat(5000))]),
        ("desconocida", vec![format!("{SESSION_COOKIE}={desconocida}")]),
        (
            "repetida en una cabecera",
            vec![format!("{SESSION_COOKIE}={id}; {SESSION_COOKIE}={id}")],
        ),
        (
            "repetida en dos cabeceras",
            vec![format!("{SESSION_COOKIE}={id}"), format!("{SESSION_COOKIE}={id}")],
        ),
        (
            "valida y ajena repetidas",
            vec![format!("{SESSION_COOKIE}={desconocida}; {SESSION_COOKIE}={id}")],
        ),
        ("nombre sin prefijo", vec![format!("bff_session={id}")]),
        ("nombre con sufijo", vec![format!("{SESSION_COOKIE}x={id}")]),
    ];
    for (nombre, cabeceras) in casos {
        for ruta in ["/auth/me", "/api/orders"] {
            let req = cabeceras
                .iter()
                .fold(Req::get(ruta), |r, c| r.header("cookie", c));
            let r = env.send(req).await;
            assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
            assert!(
                r.borra_cookie(SESSION_COOKIE),
                "{nombre} {ruta}: {:?}",
                r.set_cookies()
            );
        }
    }
    assert_eq!(env.ports.upstream().request_count(), 0);
    let ok = env.send(Req::get("/auth/me").sesion(&id)).await;
    assert_eq!(ok.status, StatusCode::OK);
}

/// Una cookie ajena con UTF-8 (o bytes que no son ASCII) junto a la de sesion no tira abajo
/// la autenticacion: solo se mira el par propio.
#[tokio::test(start_paused = true)]
async fn cookie_ajena_no_ascii_no_invalida_la_sesion() {
    let env = Env::new();
    let id = env.sesion().await;
    let casos: [Vec<u8>; 3] = [
        format!("tema=café; {SESSION_COOKIE}={id}").into_bytes(),
        format!("{SESSION_COOKIE}={id}; nombre=José 😀").into_bytes(),
        [
            b"raro=\xff\xfe; ".as_slice(),
            format!("{SESSION_COOKIE}={id}").as_bytes(),
        ]
        .concat(),
    ];
    for cabecera in casos {
        for ruta in ["/auth/me", "/api/orders"] {
            let r = env.send(Req::get(ruta).header_bytes("cookie", &cabecera)).await;
            assert_eq!(r.status, StatusCode::OK, "{ruta}");
            assert!(r.set_cookies().is_empty());
        }
    }
    // Y en cabeceras `Cookie` separadas.
    let r = env
        .send(
            Req::get("/auth/me")
                .header_bytes("cookie", "tema=café".as_bytes())
                .sesion(&id),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
}

/// Mas de 8 KiB de cookies ajenas (analiticas, etc.), bajo los 32 KiB: la sesion sigue
/// autenticando. Ya no se confunde un navegador con muchas cookies con una sesion invalida.
#[tokio::test(start_paused = true)]
async fn mas_de_8_kib_de_cookies_ajenas_siguen_autenticando() {
    let env = Env::new();
    let id = env.sesion().await;
    let ajenas = (0..6)
        .map(|i| format!("ga{i}={}", "x".repeat(2000)))
        .collect::<Vec<_>>()
        .join("; ");
    assert!(ajenas.len() > 8 * 1024 && ajenas.len() < 32 * 1024);
    for cabecera in [
        format!("{ajenas}; {SESSION_COOKIE}={id}"),
        format!("{SESSION_COOKIE}={id}; {ajenas}"),
    ] {
        for ruta in ["/auth/me", "/api/orders"] {
            let r = env.send(Req::get(ruta).header("cookie", &cabecera)).await;
            assert_eq!(r.status, StatusCode::OK, "{ruta}");
        }
    }
    let r = env
        .send(Req::get("/auth/me").header("cookie", &ajenas).sesion(&id))
        .await;
    assert_eq!(r.status, StatusCode::OK);
}

/// Una cabecera `Cookie` ilegible (mas de 32 KiB) da 401 pero no borra la cookie: no se sabe
/// si la sesion del navegador era buena, y un borrado cerraria una sesion valida. La misma
/// sesion funciona en cuanto las cabeceras vuelven a un tamano normal.
#[tokio::test(start_paused = true)]
async fn cabecera_cookie_enorme_da_401_sin_borrar_la_cookie() {
    let env = Env::new();
    let id = env.sesion().await;
    let relleno = (0..9)
        .map(|i| format!("c{i}={}", "x".repeat(4000)))
        .collect::<Vec<_>>()
        .join("; ");
    assert!(relleno.len() > 32 * 1024);
    let casos = [
        vec![format!("{relleno}; {SESSION_COOKIE}={id}")],
        vec![relleno.clone(), format!("{SESSION_COOKIE}={id}")],
        // El valor buscado supera 8 KiB.
        vec![format!("{SESSION_COOKIE}={}", "a".repeat(8 * 1024 + 1))],
    ];
    for cabeceras in casos {
        for ruta in ["/auth/me", "/api/orders"] {
            let req = cabeceras
                .iter()
                .fold(Req::get(ruta), |r, c| r.header("cookie", c));
            let r = env.send(req).await;
            assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
            assert!(r.set_cookies().is_empty(), "{ruta}: {:?}", r.set_cookies());
        }
    }
    assert_eq!(env.ports.upstream().request_count(), 0);
    let ok = env.send(Req::get("/auth/me").sesion(&id)).await;
    assert_eq!(ok.status, StatusCode::OK);
}

/// Sin cookie alguna tambien es 401 y se borra por si hubiera una vieja en el navegador.
#[tokio::test(start_paused = true)]
async fn sin_cookie_es_401_y_se_borra() {
    let env = Env::new();
    let r = env.send(Req::get("/auth/me")).await;
    assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    assert!(r.borra_cookie(SESSION_COOKIE));
}

/// Una cookie con el nombre de la sesion pero valor valido enviada como pending no sirve, y
/// la pending no abre sesion: los nombres no se intercambian.
#[tokio::test(start_paused = true)]
async fn la_cookie_pending_no_sirve_como_sesion() {
    let env = Env::new();
    let ini = env.iniciar(None).await;
    let r = env
        .send(Req::get("/auth/me").cookie(SESSION_COOKIE, &ini.pending))
        .await;
    assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    let r = env
        .send(Req::get("/auth/me").cookie(PENDING_COOKIE, &ini.pending))
        .await;
    assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
}

/// Despues del logout la cookie vieja ya no sirve (la sesion se borro del almacen, no solo
/// del navegador) y el logout es idempotente.
#[tokio::test(start_paused = true)]
async fn tras_logout_la_cookie_vieja_da_401() {
    let env = Env::new();
    let id = env.sesion().await;
    let r = env.send(Req::post("/auth/logout").csrf().sesion(&id)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(
        r.json()["logoutUrl"]
            .as_str()
            .unwrap()
            .starts_with("https://idp.test/logout")
    );
    assert!(env.ports.sessions().is_empty());
    assert_eq!(env.ports.idp().revoke_calls(), 1);

    for ruta in ["/auth/me", "/api/orders", "/auth/account/mfa"] {
        let r = env.send(Req::get(ruta).sesion(&id)).await;
        assert_error(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
        assert!(r.borra_cookie(SESSION_COOKIE));
    }
    let otra = env.send(Req::post("/auth/logout").csrf().sesion(&id)).await;
    assert_eq!(otra.status, StatusCode::OK);
    assert!(otra.borra_cookie(SESSION_COOKIE));
}

/// La cookie de login en curso se borra siempre en el callback: con exito.
#[tokio::test(start_paused = true)]
async fn pending_se_borra_en_callback_exitoso() {
    let env = Env::new();
    let s = env.login(None).await;
    assert_eq!(s.callback.status, StatusCode::SEE_OTHER);
    assert!(s.callback.borra_cookie(PENDING_COOKIE));
    assert!(env.ports.pending().is_empty());
}

/// La cookie de login en curso se borra siempre en el callback: con fallo (state ajeno,
/// error del proveedor, sin cookie).
#[tokio::test(start_paused = true)]
async fn pending_se_borra_en_callback_fallido() {
    let env = Env::new();
    for query in [
        "code=x&state=ajeno".to_owned(),
        "error=access_denied".to_owned(),
        String::new(),
    ] {
        let ini = env.iniciar(None).await;
        let r = env
            .send(Req::get(&format!("/auth/callback?{query}")).cookie(PENDING_COOKIE, &ini.pending))
            .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER);
        assert!(r.borra_cookie(PENDING_COOKIE), "{query}: {:?}", r.set_cookies());
        assert!(r.cookie_fijada(SESSION_COOKIE).is_none());
    }
    let r = env.send(Req::get("/auth/callback?code=x&state=y")).await;
    assert!(r.borra_cookie(PENDING_COOKIE));
    assert!(
        env.ports.pending().is_empty(),
        "el login en curso se consume siempre"
    );
}
