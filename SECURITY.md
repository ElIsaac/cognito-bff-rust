# Seguridad

Este documento describe el modelo de amenazas de `cognito-bff-rust`, que prueba cubre cada
amenaza y como reportar una vulnerabilidad.

## Que es y que protege

El BFF hace el login OIDC con Amazon Cognito en nombre de una SPA. Los tokens (access,
refresh, ID) viven solo en DynamoDB, nunca llegan al navegador; el navegador recibe una cookie
opaca `__Host-bff_session` (`HttpOnly; Secure; SameSite=Lax; Path=/`) y el BFF pone el access
token en las llamadas a la API propia (`/api/*`).

### Que protege

| Riesgo | Como |
|---|---|
| Robo de tokens por XSS en la SPA | Los tokens no existen en el navegador; la cookie es `HttpOnly`. |
| CSRF | Cabecera obligatoria en metodos que cambian estado, `Sec-Fetch-Site` y `Origin` verificados. |
| Open redirect | `ReturnTo` valida el destino del login; los destinos de error y de logout son fijos. |
| Login CSRF y fijacion de sesion | Cookie `__Host-bff_pending` ligada a un `PENDING#` de un solo uso; el ID de sesion se regenera en cada login. |
| Replay y sustitucion en OIDC | `state` en tiempo constante, `nonce`, PKCE S256, pending consumido de forma atomica. |
| ID token falsificado | Algoritmo fijo RS256, `iss`, `aud`, `exp`, `iat`, `token_use` y `nonce` verificados; JWKS con limite de descargas. |
| Secuestro de sesion por lectura de la tabla | La clave es `sha256(id)`; un volcado de la tabla no da cookies validas. |
| SSRF y escape de prefijo en el proxy | `ProxyPath` rechaza `.`/`..`, separadores codificados y esquemas; el host destino sale solo de la configuracion. |
| Fuga de credenciales hacia el upstream | Lista blanca de cabeceras; `Cookie`, `Host`, `X-Forwarded-*` y `Authorization` del cliente nunca viajan. |
| Fugas en logs, `Debug` y errores | Tipos secretos con `Debug` redactado, errores de lista blanca con `requestId`, sin detalles internos. |
| Saltarse CloudFront | `X-Origin-Verify` en tiempo constante, con rotacion (`AWSPREVIOUS`); falla cerrado. |
| Refresh concurrente y logouts espurios | Lease en DynamoDB: exactamente un refresh por sesion aunque lleguen cientos de peticiones. |
| Escalada de privilegios en el despliegue | Los roles `gh-deploy-<env>` solo crean roles con la permissions boundary del bootstrap (`infra/bootstrap`). |

### Que no protege

- **XSS en la SPA en si.** El BFF evita que robe tokens, pero un XSS puede llamar al BFF con la
  sesion del usuario mientras la pestana este abierta. Usa una CSP estricta (el modulo
  `cloudfront` trae una por omision).
- **Compromiso de la cuenta AWS** o de las credenciales de quien despliega: quien lee Secrets
  Manager o la tabla con permisos suficientes tiene las sesiones y el client secret.
- **Phishing y robo de credenciales del usuario**, fatiga de MFA y malware en el equipo del
  usuario.
- **Bugs o autorizacion debil del upstream.** El BFF autentica y reenvia; que el usuario pueda
  hacer algo lo decide la API propia con el access token.
- **Denegacion de servicio volumetrica.** Hay limites (cuerpo, tiempo, longitud de cabeceras y
  query) pero no hay limitacion de tasa: eso va en WAF o en el CDN.
- **Subdominios hermanos o `localhost` compartido.** Las cookies `__Host-` no se pueden fijar
  desde otro subdominio, pero un navegador comprometido o una extension maliciosa ve todo.

### Supuestos

1. TLS de extremo a extremo (visitante, CloudFront, API Gateway, Cognito, upstream). El BFF solo
   emite cookies `Secure`; `http` solo se acepta para `localhost` y con la feature `local`.
2. Cognito esta bien configurado: client confidencial, rotacion de refresh tokens, callback
   URLs exactas, y una validez del refresh token no menor que `SESSION_ABSOLUTE_TTL_SECS`.
3. CloudFront es el unico punto de entrada. Con `X-Origin-Verify` activado, llamar directo a
   API Gateway da `403`. Si lo desactivas, ese endpoint es publico.
4. La SPA y el BFF comparten origen (`PUBLIC_ORIGIN`), de modo que no hay CORS ni cookies
   entre sitios.
5. El estado de OpenTofu se cifra (`encryption` con `enforced = true`): contiene el client
   secret y el secreto de `X-Origin-Verify` si los crea el modulo.
6. El reloj de Lambda es correcto; hay una tolerancia de 60 s para `iat` y `exp`.

## Amenaza, pruebas y mitigacion

Las rutas son relativas a `crates/`. `seg` = `workspace-tests/tests/security`, `http` =
`workspace-tests/tests/http`, `contrato` = `workspace-tests/tests/contrato`, `oidc` =
`adapters/oidc-cognito/tests/integracion`. `fuzz` = `fuzz/fuzz_targets`.

| Amenaza | Pruebas que la cubren | Mitigacion |
|---|---|---|
| Robo de tokens por XSS | `http/me.rs::me_devuelve_solo_el_perfil_sin_tokens`; `http/cookies.rs::cookie_de_sesion_es_un_id_opaco_de_43_caracteres`; `http/cookies.rs::cookies_del_callback_exitoso_llevan_atributos_fijos`; `seg/fugas.rs::tracing_no_contiene_secretos_en_ningun_flujo` | Tokens solo en DynamoDB; cookie opaca con `HttpOnly; Secure; SameSite=Lax; Path=/` y prefijo `__Host-`; `/auth/me` devuelve solo el perfil. |
| CSRF en `/auth/*` y `/api/*` | `seg/csrf.rs::metodos_inseguros_sin_cabecera_se_rechazan`; `seg/csrf.rs::sec_fetch_site_ajeno_se_rechaza`; `seg/csrf.rs::origin_ajeno_se_rechaza`; `http/csrf.rs::sin_cabecera_x_requested_with_es_403`; `http/csrf.rs::origin_duplicado_es_403`; `http/csrf.rs::csrf_se_evalua_antes_que_la_sesion`; `http/csrf.rs::metodos_desconocidos_dan_405` | Middleware CSRF: cabecera `CSRF_HEADER_NAME` presente, `Sec-Fetch-Site` same-origin o none, `Origin` igual a `PUBLIC_ORIGIN`; se evalua antes de mirar la sesion. |
| Open redirect via `returnTo` | `domain/src/return_to.rs::rechaza_ataques_conocidos`; `domain/src/return_to.rs::aceptado_conserva_el_host` (proptest); `domain/src/return_to.rs::ascii_hostil_conserva_el_host` (proptest); `domain/src/return_to.rs::fragmentos_peligrosos` (proptest); `seg/oidc.rs::return_to_externo_se_descarta`; `http/login.rs::return_to_hostil_termina_en_la_raiz`; `http/login.rs::ya_autenticado_con_return_to_hostil_va_a_la_raiz`; `http/callback.rs::el_destino_del_error_es_fijo`; `fuzz/return_to.rs` | `ReturnTo` solo admite rutas locales con una `/` inicial, sin `\`, `@` ni `%` peligroso; los destinos de error y logout salen de la configuracion. |
| Login CSRF (completar un login ajeno) | `seg/oidc.rs::callback_sin_cookie_pending_se_rechaza`; `seg/oidc.rs::state_de_otro_pending_se_rechaza`; `http/callback.rs::sin_cookie_pending_es_missing_pending`; `http/callback.rs::state_incorrecto_es_invalid_state`; `http/callback.rs::state_duplicado_se_rechaza` | Cookie `__Host-bff_pending` + item `PENDING#` ligados al navegador; `state` comparado en tiempo constante. |
| Replay del callback, `code` robado | `seg/oidc.rs::replay_del_callback_falla`; `seg/oidc.rs::code_reutilizado_en_otro_login_falla`; `seg/oidc.rs::code_con_verifier_ajeno_falla`; `seg/oidc.rs::nonce_distinto_no_crea_sesion`; `http/callback.rs::replay_del_callback_es_invalid_state`; `contrato/suite.rs::pending_se_consume_una_sola_vez`; `contrato/suite.rs::consume_concurrente_devuelve_una_sola_vez` | PKCE S256, `nonce`, y `consume` atomico (borrado condicional) del pending antes de mirar nada mas. |
| `error=` del proveedor reflejado | `seg/oidc.rs::error_access_denied_no_crea_sesion`; `seg/oidc.rs::error_desconocido_es_provider_error_y_no_se_refleja`; `http/callback.rs::el_redirect_de_error_no_refleja_error_description`; `http/callback.rs::ningun_fallo_fija_sesion` | Lista blanca de codigos; nunca se refleja `error_description`; un fallo no deja cookie de sesion. |
| ID token falsificado o mal validado | `oidc/id_token.rs::alg_none`; `oidc/id_token.rs::alg_hs256_firmado_con_la_llave_publica`; `oidc/id_token.rs::algoritmos_distintos_de_rs256`; `oidc/id_token.rs::firma_de_otra_llave_con_el_mismo_kid`; `oidc/id_token.rs::issuer_distinto`; `oidc/id_token.rs::audience_distinta`; `oidc/id_token.rs::exp_vencido_mas_alla_del_leeway`; `oidc/id_token.rs::iat_en_el_futuro`; `oidc/id_token.rs::nonce_distinto`; `oidc/id_token.rs::token_use_access`; `oidc/id_token.rs::kid_desconocido`; `oidc/id_token.rs::jwk_embebido_en_el_header_se_ignora`; `oidc/refresh.rs::refresh_con_id_token_falsificado_se_rechaza` | Algoritmo fijo RS256, claims obligatorios, `kid` buscado solo en el JWKS del issuer; `email` solo con `email_verified`. |
| JWKS usado para amplificar carga | `oidc/jwks.rs::kids_inventados_no_provocan_mas_de_una_descarga_por_ventana`; `oidc/jwks.rs::kids_inventados_con_jwks_caido_no_deben_martillar_a_cognito`; `oidc/jwks.rs::jwks_vencido_con_cognito_caido_usa_el_cache_anterior` | Cache con TTL y una descarga como maximo por ventana, aunque falle. |
| Fijacion de sesion | `seg/oidc.rs::fijacion_de_sesion_borra_la_anterior_y_regenera_id`; `seg/oidc.rs::cookie_plantada_inexistente_no_se_adopta`; `http/cookies.rs::fijacion_de_sesion_id_nuevo_y_la_vieja_se_borra`; `http/cookies.rs::cada_login_tiene_un_session_id_nuevo` | ID nuevo de 256 bits en cada login; la sesion anterior se borra; una cookie plantada nunca se adopta. |
| Cookie manipulada o ambigua | `seg/sesiones.rs::cookies_manipuladas_son_unauthorized`; `http/cookies.rs::cookies_hostiles_dan_401_y_se_borran`; `http/cookies.rs::la_cookie_pending_no_sirve_como_sesion`; `http/callback.rs::pending_malformada_o_repetida_es_missing_pending`; `fuzz/cookie_header.rs` | Parser propio y acotado: cabecera <= 8 KiB, valor base64url <= 128 bytes, nombre repetido = ausente; un valor malformado es "sin cookie" (`401`). |
| Volcado de la tabla de sesiones | `http/login.rs::login_redirige_al_idp_y_guarda_la_pending_por_hash`; `seg/ws_ticket.rs::boleto_guardado_por_hash_de_un_solo_uso`; `contrato/suite.rs::namespaces_separados_por_prefijo` | La clave de particion es `sha256(id)`; el ID en claro solo vive en la cookie. |
| Sesion que no muere | `seg/sesiones.rs::logout_borra_sesion_revoca_refresh_e_invalida_la_cookie`; `seg/sesiones.rs::logout_borra_la_sesion_aunque_la_revocacion_falle`; `seg/sesiones.rs::inactividad_mayor_a_12_horas_cierra_la_sesion`; `seg/sesiones.rs::vida_absoluta_se_respeta_aunque_haya_actividad`; `seg/sesiones.rs::sesion_vencida_aun_en_la_tabla_se_rechaza_y_borra`; `http/cookies.rs::tras_logout_la_cookie_vieja_da_401` | Vida absoluta e inactividad verificadas en codigo (no solo con el TTL de DynamoDB); logout borra y revoca el refresh token. |
| SSRF y escape del prefijo `/api/` | `domain/src/proxy_path.rs::rechaza_escapes_del_prefijo`; `domain/src/proxy_path.rs::https_evil_no_cambia_host`; `seg/proxy.rs::rutas_invalidas_son_bad_request_sin_llamar_a_nadie`; `http/proxy.rs::rutas_hostiles_dan_400_sin_llegar_al_upstream`; `http/proxy.rs::el_host_no_se_puede_cambiar`; `fuzz/proxy_path.rs` | `ProxyPath`: ASCII visible, sin `\`, `?`, `#`, sin segmentos `.`/`..` ni `%2e`, `%2f`, `%5c`, `%00`; el destino es siempre `UPSTREAM_BASE_URL` + ruta. |
| Credenciales hacia el upstream, cookies de vuelta | `seg/proxy.rs::cabeceras_prohibidas_no_llegan_al_upstream`; `http/proxy.rs::cabeceras_prohibidas_no_llegan_al_upstream`; `seg/proxy.rs::el_bearer_es_el_access_token_refrescado`; `seg/proxy.rs::set_cookie_y_cabeceras_peligrosas_del_upstream_no_vuelven`; `http/proxy.rs::set_cookie_del_upstream_se_elimina`; `http/origin_verify.rs::la_cabecera_no_se_reenvia_al_upstream` | Lista blanca de cabeceras de ida y de vuelta; el unico `Authorization` es el `Bearer` del access token de la sesion. |
| Abuso de recursos del proxy | `seg/proxy.rs::body_mayor_al_limite_es_payload_too_large`; `seg/proxy.rs::el_limite_de_body_tiene_tope_duro`; `seg/proxy.rs::upstream_lento_es_upstream_timeout`; `http/proxy.rs::cuerpo_mayor_al_limite_es_413`; `http/login.rs::query_enorme_se_ignora`; `http/account.rs::cuerpo_de_mas_de_4_kib_es_413`; `fuzz/callback_query.rs` | Cuerpo <= `PROXY_MAX_BODY_BYTES` (tope duro 5 MiB), timeout, query <= 8 KiB, cuerpos de cuenta <= 4 KiB. |
| Refresh concurrente, logouts espurios | `seg/refresh.rs::refresh_con_20_tareas_llama_una_sola_vez`; `seg/refresh.rs::refresh_con_200_tareas_llama_una_sola_vez`; `seg/refresh.rs::refresh_con_50_tareas_en_hilos_reales_llama_una_sola_vez`; `seg/refresh.rs::lease_huerfano_se_recupera_tras_10_segundos`; `seg/refresh.rs::invalid_grant_borra_la_sesion_con_una_sola_llamada`; `seg/refresh.rs::rotacion_guarda_el_refresh_nuevo_e_invalida_el_viejo`; `seg/refresh.rs::logout_durante_un_refresh_no_resucita_la_sesion`; `contrato/suite.rs::carrera_de_50_leases_un_solo_ganador` | Lease condicional en DynamoDB antes de llamar a Cognito, ademas de `version`; timeout del IdP menor que el lease. |
| Fugas en logs, `Debug` y respuestas | `seg/fugas.rs::tracing_no_contiene_secretos_en_ningun_flujo`; `seg/fugas.rs::debug_de_los_tipos_con_secretos_esta_redactado`; `http/fugas.rs::tracing_no_contiene_secretos_en_ningun_flujo_http`; `oidc/fugas.rs::ningun_log_contiene_secretos`; `oidc/canje.rs::debug_del_adaptador_no_incluye_secretos`; `http/errores.rs::todos_los_errores_tienen_la_misma_forma`; `http/proxy.rs::timeout_y_caida_del_upstream_no_filtran_detalles`; `seg/proxy.rs::los_errores_publicos_solo_exponen_codigos_estables` | Tipos secretos con `Debug` `[REDACTED]` y sin `Display`; errores `{"error","requestId"}` de lista blanca; el span usa la ruta registrada, nunca la query. |
| Respuestas cacheadas con datos de sesion | `http/errores.rs::las_respuestas_de_auth_son_no_store`; `http/account.rs::associate_devuelve_el_secreto_sin_cache` | `Cache-Control: no-store` en las respuestas; CloudFront con `CachingDisabled` en `/auth/*` y `/api/*`. |
| Llamar al origen sin pasar por CloudFront | `http/origin_verify.rs::sin_cabecera_es_403`; `http/origin_verify.rs::valor_incorrecto_es_403`; `http/origin_verify.rs::cabecera_duplicada_es_403`; `http/origin_verify.rs::rotacion_acepta_el_valor_anterior`; `http/origin_verify.rs::error_del_proveedor_de_secretos_falla_cerrado` | `X-Origin-Verify` en tiempo constante contra `AWSCURRENT` y `AWSPREVIOUS`; si Secrets Manager falla, `500` (cierra). |
| Secreto del client rotado o filtrado | `oidc/token_endpoint.rs::invalid_client_rota_el_secreto_y_reintenta_una_vez`; `oidc/token_endpoint.rs::invalid_client_persistente_es_permanente_sin_tercer_intento`; `oidc/token_endpoint.rs::fallo_del_secret_provider_no_llama_a_cognito` | Cache TTL y recarga forzada con un solo reintento ante `invalid_client`. |
| Boleto de WebSocket robado o reutilizado | `seg/ws_ticket.rs::sin_sesion_no_hay_boleto`; `seg/ws_ticket.rs::boleto_guardado_por_hash_de_un_solo_uso`; `seg/ws_ticket.rs::cada_boleto_es_distinto`; `http/ws_ticket.rs::tras_logout_no_hay_boleto`; `contrato/suite.rs::ticket_se_consume_una_sola_vez` | Boleto de 256 bits, 30 s, guardado por hash y consumido de forma atomica; viaja en `Sec-WebSocket-Protocol`, nunca en la URL. |
| Abuso de los endpoints de cuenta y MFA | `http/account.rs::sin_sesion_todo_es_401`; `http/account.rs::toda_llamada_de_cuenta_usa_el_access_token_de_la_sesion`; `http/account.rs::cuerpos_malformados_son_400`; `http/account.rs::content_type_no_json_es_415`; `http/account.rs::rechazos_y_fallos_de_cognito_tienen_codigos_estables`; `http/csrf.rs::con_cabecera_y_origin_propios_pasa` | CSRF y sesion obligatorios; JSON acotado con campos desconocidos rechazados; errores de Cognito mapeados a una lista blanca. |
| Dependencias que rompen los limites de capas | `workspace-tests/tests/architecture.rs::el_workspace_respeta_los_limites_de_arquitectura`; `architecture.rs::domain_con_dependencia_transitiva_prohibida_falla`; `architecture.rs::adaptador_no_puede_depender_de_otro_adaptador_ni_de_lambda` | Test sobre `cargo metadata`; `cargo deny` y `cargo audit` en CI (advisories, licencias, fuentes). |
| Escalada de privilegios con `gh-deploy-<env>` | `tofu validate`, `tflint` y `trivy config` en CI (no hay pruebas de comportamiento: la politica se verifica al aplicar) | Permissions boundary obligatoria en `CreateRole`, `PutRolePolicy`, `AttachRolePolicy` y `PutRolePermissionsBoundary`; `Deny` a quitarla y a tocar su politica. Ver `infra/bootstrap/README.md`. |

## Pruebas de seguridad y como correrlas

```sh
cargo test --workspace                                   # con DYNAMODB_ENDPOINT_URL (DynamoDB Local)
cargo +nightly fuzz run return_to -- -max_total_time=60  # desde fuzz/, ver README
```

Cada prueba de `workspace-tests/tests/security` documenta el ataque que cubre. Los fuzz targets
estan en `fuzz/fuzz_targets` y los casos semilla en `fuzz/seeds`. El workflow `zap.yml` corre
un escaneo pasivo (ZAP baseline) contra una URL desplegada.

## Reporte de vulnerabilidades

No abras un issue publico. Usa los **GitHub private advisories** del repositorio: pestana
*Security* -> *Report a vulnerability* (`https://github.com/ElIsaac/cognito-bff-rust/security/advisories/new`).

Incluye version o commit, pasos para reproducir y el impacto que ves. Se acusa recibo en un
plazo de 7 dias y se trabaja la correccion de forma privada; la divulgacion se coordina contigo
una vez publicada la version corregida. Solo se da soporte a la rama `main`.

Fuera de alcance: hallazgos que dependan de una SPA vulnerable, de un Cognito mal configurado o
de credenciales de AWS ya comprometidas (ver "Que no protege").
