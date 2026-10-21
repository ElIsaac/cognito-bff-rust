# cognito-bff-rust

BFF (Backend for Frontend) de autenticacion para una SPA servida por CloudFront, con Amazon
Cognito como proveedor de identidad. Rust, Lambda ARM64, sesiones en DynamoDB. **Los tokens
nunca llegan al navegador**: la SPA solo tiene una cookie opaca `__Host-bff_session`, y el BFF
pone el access token en las llamadas a tu API.

- Login OIDC con codigo + PKCE, `state` y `nonce`; ID token validado con RS256 y JWKS.
- Sesiones en DynamoDB con refresh automatico y un solo refresh por sesion aunque lleguen
  cientos de peticiones a la vez.
- Proxy `/api/*` hacia tu API con lista blanca de cabeceras y rutas validadas.
- CSRF, cookies `__Host-`, `X-Origin-Verify` desde CloudFront, errores con `requestId`.
- Cambio de contrasena y MFA (TOTP) de Cognito sin exponer tokens.
- Modulos OpenTofu: `bff` (Lambda, HTTP API, tabla, secretos) y `cloudfront` (SPA + BFF en el
  mismo origen).

Repositorio publico y reutilizable: nada de una cuenta concreta esta en el codigo, todo entra
por variables. Ejemplos con `example.com`.

## Arquitectura

Hexagonal: `domain` (tipos y reglas puras) y `application` (puertos y casos de uso) no conocen
AWS ni HTTP; los adaptadores (`http-axum`, `oidc-cognito`, `session-dynamodb`, `secrets-aws`,
`upstream-reqwest`, `in-memory`) implementan los puertos y `lambda` los cablea. Un test lee
`cargo metadata` y falla si se rompe una regla de dependencias. Diagrama, puertos, flujos y
la guia "como reemplazar un adaptador": [docs/architecture.md](docs/architecture.md).

## Contrato para la SPA

Todo va al mismo origen que la SPA (`PUBLIC_ORIGIN`): sin CORS, con `credentials: 'same-origin'`.

Guia completa para el frontend (cliente TypeScript, WebSocket, migracion desde tokens en el navegador, trampas): [docs/frontend.md](docs/frontend.md).

**CSRF.** Toda peticion `POST`, `PUT`, `PATCH` o `DELETE` a `/auth/*` y `/api/*` debe llevar la
cabecera `X-Requested-With` (el nombre se cambia con `CSRF_HEADER_NAME`; el valor no importa,
por ejemplo `fetch`). Si el navegador manda `Origin` o `Sec-Fetch-Site`, deben ser del mismo
origen. Si no: `403 {"error":"csrf"}`. Los `GET` nunca cambian estado.

| Ruta | Metodo | Respuesta |
|---|---|---|
| `/auth/login?returnTo=/ruta` | GET | `303` a Cognito (o a `returnTo` si ya hay sesion). `returnTo` debe ser una ruta local; si no, se usa `/`. Navega con `location.assign`, no con `fetch`. |
| `/auth/callback` | GET | Lo llama Cognito. `303` a `returnTo` con la cookie de sesion; si falla, `303` a `AUTH_ERROR_REDIRECT_PATH?code=<codigo>`. |
| `/auth/me` | GET | `200` con el perfil; `401` si no hay sesion (anonimo). |
| `/auth/logout` | POST | `200 {"logoutUrl": "..."}`; la SPA hace `location.assign(logoutUrl)`. Idempotente. |
| `/auth/ws-ticket` | POST | `200 {"ticket": "...", "expiresIn": 30}`. Boleto de un solo uso para abrir un WebSocket. |
| `/auth/account/mfa` | GET | `200 {"totp": "enabled" \| "disabled"}` |
| `/auth/account/mfa/totp/associate` | POST | `200 {"secret": "..."}`; la SPA arma el QR con el email de `/auth/me`. |
| `/auth/account/mfa/totp/verify` | POST | Cuerpo `{"code": "123456", "deviceName": "..."}` (`deviceName` opcional). `204`. |
| `/auth/account/mfa/preference` | POST | Cuerpo `{"totp": true}`. `204`. |
| `/auth/account/change-password` | POST | Cuerpo `{"previousPassword": "...", "proposedPassword": "..."}`. `204`. |
| `/api/*` | cualquiera | Proxy a `UPSTREAM_BASE_URL/<ruta>?<query>` con `Authorization: Bearer <access>` (o firmada con SigV4 con `UPSTREAM_AUTH=aws_iam`). Status y cuerpo del upstream tal cual; sin `Set-Cookie`. |

Los cuerpos de `/auth/account/*` son `application/json` de hasta 4 KiB y no admiten campos
desconocidos.

### `/auth/me`

```json
{
  "sub": "1b2c-3d4e",
  "email": "ana@example.com",
  "name": "Ana Perez",
  "groups": ["ventas"],
  "attributes": { "custom:tenant_id": "t-42" }
}
```

`email` y `name` pueden ser `null`. `attributes` contiene solo los claims de `EXPOSED_CLAIMS`.
Nunca hay tokens.

### Errores

Todo error de `/auth/*` y `/api/*` generado por el BFF tiene la misma forma, con `no-store`:

```json
{ "error": "unauthenticated", "requestId": "Zx3k9A2qIAMEJ6w=" }
```

| Estado | `error` |
|---|---|
| 400 | `bad_request`, y en cuenta: `code_mismatch`, `code_expired`, `not_authorized`, `invalid_password`, `mfa_setup_invalid` |
| 401 | `unauthenticated` (ademas borra la cookie de sesion) |
| 403 | `csrf`, `forbidden` |
| 404, 405, 415 | `not_found`, `method_not_allowed`, `unsupported_media_type` |
| 413 | `payload_too_large` |
| 429 | `too_many_requests` (cuenta) |
| 500 | `internal` |
| 502, 504 | `upstream_unavailable`, `upstream_timeout` |
| 503 | `busy` (con `Retry-After: 1`): no se pudo refrescar la sesion a tiempo; reintenta |

`requestId` es el mismo valor de la cabecera `X-Request-ID`, presente en **todas** las
respuestas; incluyelo al reportar un problema. En `401`, la SPA llama a `login()`; en el
arranque, un `401` de `/auth/me` solo significa "anonimo".

```ts
const csrf = { 'X-Requested-With': 'fetch' };
export const login = () =>
  location.assign('/auth/login?returnTo=' + encodeURIComponent(location.pathname + location.search));
export const getUser = async () => {
  const r = await fetch('/auth/me', { credentials: 'same-origin' });
  return r.ok ? r.json() : null;
};
export const logout = async () => {
  const r = await fetch('/auth/logout', { method: 'POST', headers: csrf, credentials: 'same-origin' });
  location.assign((await r.json()).logoutUrl);
};
export const apiFetch = (path: string, init: RequestInit = {}) =>
  fetch('/api/' + path, {
    ...init,
    credentials: 'same-origin',
    headers: { ...csrf, ...init.headers },
  });
```

## Configuracion

El Lambda se configura por variables de entorno (el modulo `bff` las rellena). Se validan al
arrancar: un valor invalido falla de inmediato y el error nombra la variable, nunca su valor.

| Variable | Por defecto | Descripcion |
|---|---|---|
| `PUBLIC_ORIGIN` | requerida | `https://app.example.com`, sin barra final; `http` solo para `localhost`. Se normaliza al origen serializado (host en minusculas, sin `:443`), que es lo que el navegador manda en `Origin`. |
| `COGNITO_ISSUER` | requerida | `https://cognito-idp.<region>.amazonaws.com/<poolId>` |
| `COGNITO_DOMAIN` | requerida | Dominio del Hosted UI / Managed Login, con `https://`. |
| `COGNITO_CLIENT_ID` | requerida | App client confidencial. |
| `COGNITO_CLIENT_SECRET_ARN` | requerida | Secreto de Secrets Manager con el client secret. |
| `OIDC_SCOPES` | `openid email profile` | |
| `SESSIONS_TABLE` | requerida | Tabla DynamoDB (`pk` string, TTL en el atributo `ttl`). |
| `UPSTREAM_BASE_URL` | requerida | Tu API, sin barra final. |
| `UPSTREAM_AUTH` | `none` | `none`: `Authorization: Bearer <access>`. `aws_iam`: el upstream es una Function URL con `AuthType: AWS_IAM`; cada peticion se firma con SigV4 (servicio `lambda`) con las credenciales del rol de la Lambda y el access token, crudo, viaja en `UPSTREAM_TOKEN_HEADER`. |
| `UPSTREAM_TOKEN_HEADER` | requerida con `aws_iam` | Cabecera del access token; en minusculas, distinta de `authorization`, `host`, `cookie` y `x-amz-*`. Se valida al arrancar. |
| `UPSTREAM_AWS_REGION` | `AWS_REGION` | Region de la firma SigV4 (la de la Function URL). |
| `ORIGIN_VERIFY_SECRET_ARN` | vacio | Secreto de `X-Origin-Verify`; vacio = desactivado. Si el valor no coincide, el secreto se recarga una vez (como mucho cada 30 s) antes de responder `403`. |
| `ORIGIN_VERIFY_PREVIOUS_GRACE_SECS` | `900` | Cuanto vale el valor anterior (`AWSPREVIOUS`) desde que el BFF ve el actual. |
| `COOKIE_NAME` | `__Host-bff_session` | Debe empezar por `__Host-`. |
| `CSRF_HEADER_NAME` | `X-Requested-With` | |
| `SESSION_ABSOLUTE_TTL_SECS` | `2592000` (30 d) | Vida maxima; no la pongas por encima de la validez del refresh token en Cognito. |
| `SESSION_IDLE_TTL_SECS` | `43200` (12 h) | Inactividad. |
| `ACCESS_REFRESH_THRESHOLD_SECS` | `60` | Se refresca cuando al access token le queda menos que esto. |
| `REFRESH_LEASE_SECS` | `10` | Duracion del lease de refresh. |
| `IDP_TIMEOUT_SECS` | `4` | Timeout HTTP hacia Cognito; debe ser menor que `REFRESH_LEASE_SECS`. |
| `PENDING_TTL_SECS` | `600` | Vida del login en curso. |
| `PROXY_MAX_BODY_BYTES` | `1048576` | Tope del cuerpo del proxy; tope duro de 5 MiB. |
| `PROXY_TIMEOUT_SECS` | `10` | Timeout del upstream; rige el menor entre este y lo que quede de `REQUEST_BUDGET_SECS`. |
| `REQUEST_BUDGET_SECS` | `14` | Presupuesto total de una peticion a `/api/*`, contado desde que entra; un refresh lento lo consume. Con el modulo `bff` vale `lambda_timeout_secs - 1`. |
| `JWKS_CACHE_TTL_SECS` | `3600` | |
| `SECRET_CACHE_TTL_SECS` | `600` | |
| `LOGOUT_REDIRECT_PATH` | `/` | Ruta local a la que vuelve Cognito tras el logout. |
| `AUTH_ERROR_REDIRECT_PATH` | `/` | Ruta local de un login fallido; se le agrega `?code=`. |
| `EXPOSED_CLAIMS` | vacio | Claims extra de `/auth/me`, separados por coma (p. ej. `custom:tenant_id`). |
| `WS_TICKET_TTL_SECS` | `30` | Vida del boleto de WebSocket (maximo 120). |
| `RUST_LOG` | `info` | Filtro de `tracing`; los logs salen en JSON. |

El arranque lee `COGNITO_CLIENT_SECRET_ARN` y `ORIGIN_VERIFY_SECRET_ARN` (si esta): un permiso o un
nombre equivocado impide arrancar, en vez de fallar en la primera peticion.

Solo con `--features local`: `DYNAMODB_ENDPOINT_URL` (DynamoDB Local), `COGNITO_CLIENT_SECRET` y
`ORIGIN_VERIFY_SECRET` (los secretos en claro, sin Secrets Manager) y `LOCAL_ADDR` (por omision
`127.0.0.1:8787`).

## Desarrollo local

Requisitos: Rust (la version la fija `rust-toolchain.toml`), Docker y un app client de Cognito
con `http://localhost:5173/auth/callback` como callback URL.

```sh
# 1. DynamoDB Local y la tabla
docker run -d --name bff-dynamodb -p 8000:8000 amazon/dynamodb-local:2.5.0
export AWS_REGION=us-east-2 AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local
aws dynamodb create-table --endpoint-url http://localhost:8000 --table-name bff-sessions \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH --billing-mode PAY_PER_REQUEST

# 2. Configuracion
cp .env.example .env     # rellena issuer, dominio, client id y secret

# 3. El BFF en http://127.0.0.1:8787
set -a; . ./.env; set +a
cargo run -p lambda --features local
```

Pon el dev server de la SPA con proxy de `/auth` y `/api` hacia el BFF para
que todo sea del mismo origen (las cookies `__Host-` funcionan en `http://localhost`):

```ts
// vite.config.ts
export default defineConfig({
  server: {
    port: 5173,
    proxy: {
      '/auth': 'http://127.0.0.1:8787',
      '/api': 'http://127.0.0.1:8787',
    },
  },
});
```

## Despliegue

`infra/` trae los modulos OpenTofu y un ejemplo; las instancias reales (con tus valores) viven
en tu propio repo. Compila el zip con
`cargo lambda build --release --arm64 --output-format zip -p lambda` y referencia los
modulos por commit:

```hcl
module "bff" {
  source = "git::https://github.com/ElIsaac/cognito-bff-rust.git//infra/modules/bff?ref=<sha-de-40-caracteres>"

  name                 = "mi-bff-dev"
  lambda_zip_path      = "../target/lambda/lambda/bootstrap.zip"
  public_origin        = "https://app.example.com"
  cognito_issuer       = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_EXAMPLE"
  cognito_domain       = "https://auth.example.com"
  create_app_client    = true
  cognito_user_pool_id = "us-east-2_EXAMPLE"
  upstream_base_url    = "https://api.example.com"
}
```

El estado de OpenTofu **contiene secretos** (el client secret y el de `X-Origin-Verify`) y debe
ir cifrado. `infra/bootstrap` crea el bucket de estado, la llave KMS y los roles de deploy de
GitHub con una permissions boundary. Todo, con la guia paso a paso, en
[docs/infra.md](docs/infra.md) y `infra/bootstrap/README.md`.

## Pruebas

```sh
export DYNAMODB_ENDPOINT_URL=http://localhost:8000   # DynamoDB Local, para los tests de contrato
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check && cargo audit
node --test infra/modules/cloudfront/functions/*.test.mjs
```

- `crates/workspace-tests/tests/security`: la suite de seguridad; cada prueba documenta el
  ataque que cubre.
- `.../tests/http`: la capa HTTP completa con fakes (cookies, CSRF, proxy, errores).
- `.../tests/contrato`: la misma bateria contra el fake y contra DynamoDB Local.
- `.../tests/architecture.rs`: los limites entre crates.
- `crates/adapters/oidc-cognito/tests/integracion`: validacion de tokens con un JWKS de prueba.

### Fuzzing

`fuzz/` es un crate de `cargo-fuzz` fuera del workspace, con cuatro targets: `return_to`,
`proxy_path`, `cookie_header` y `callback_query`. Requiere un nightly.

```sh
cargo install cargo-fuzz --version 0.12.0 --locked
cd fuzz
mkdir -p corpus/return_to
cargo +nightly fuzz run return_to corpus/return_to seeds/return_to -- -max_total_time=60
```

`fuzz/seeds/` tiene los casos semilla; `fuzz/corpus` y `fuzz/artifacts` estan ignorados. Los
parsers privados de `http-axum` se exponen solo con la feature `fuzzing`.

### CI

`.github/workflows/ci.yml` corre todo lo anterior sin AWS: fmt, clippy, tests con DynamoDB
Local, `cargo deny` y `audit`, gitleaks, validacion de la infra (`tofu fmt`, `validate`,
`tflint`, `trivy config`), el test de Node y una pasada corta de fuzzing. `zap.yml` lanza un
escaneo ZAP baseline a mano contra una URL. Los workflows se prueban con `act` y `actionlint`.

## Seguridad

Modelo de amenazas, que protege y que no, tabla amenaza -> pruebas -> mitigacion y la politica
de reporte (GitHub private advisories): [SECURITY.md](SECURITY.md).

## Licencia

Doble licencia, a tu eleccion: [Apache-2.0](LICENSE-APACHE) o [MIT](LICENSE-MIT).
