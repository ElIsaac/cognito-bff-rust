# Guia de integracion para el frontend

Como consumir el BFF desde una SPA (React, Vue, Svelte, Angular o JS plano). El contrato
completo vive en el [README](../README.md); aqui esta lo que la SPA debe asumir, un cliente
pequeno en TypeScript y las trampas conocidas.

## 1. Lo que la SPA debe asumir

- **Mismo sitio.** La SPA y el BFF salen del mismo origen (`https://app.example.com`) detras de
  CloudFront: `/auth/*` y `/api/*` van al BFF, todo lo demas a S3. No hay CORS ni dominios
  cruzados.
- **Cookie `__Host-bff_session`.** `HttpOnly; Secure; SameSite=Lax; Path=/`, opaca (un ID, no
  un JWT). La SPA no la lee ni la escribe; el navegador la manda sola.
- **El navegador nunca ve tokens.** No hay access token, ID token ni refresh token en JS,
  `localStorage` ni URL. El BFF pone el `Authorization: Bearer` al llamar a tu API.
- **Estado de sesion = `GET /auth/me`.** Un `401` ahi significa "anonimo", no "error".
- **Todo lo del BFF es `no-store`.** No cachees respuestas de `/auth/*` en la SPA.

## 2. Endpoints

Todos los cuerpos son `application/json`. Los `POST` de `/auth/account/*` aceptan hasta 4 KiB y
rechazan campos desconocidos (`400 bad_request`); si el `Content-Type` no es JSON, `415`.

### Login y sesion

| Ruta | Metodo | Respuesta |
|---|---|---|
| `/auth/login?returnTo=/ruta` | GET | `303` a Cognito, o a `returnTo` si ya hay sesion. Solo se aceptan rutas propias relativas (empiezan con una `/`); cualquier otra cosa (URL absoluta, `//host`, `\`, `returnTo` repetido) cae en `/`. Navega con `location.assign`, nunca con `fetch`. |
| `/auth/callback` | GET | Lo maneja el BFF, la SPA no lo llama. `303` a `returnTo` con la cookie; si falla, `303` a `AUTH_ERROR_REDIRECT_PATH?code=<codigo>`. |
| `/auth/me` | GET | `200` con el perfil; `401` si no hay sesion. |
| `/auth/logout` | POST | `200 {"logoutUrl": "..."}` y borra la cookie. Idempotente. |
| `/auth/ws-ticket` | POST | `200 {"ticket": "...", "expiresIn": 30}` |

Codigos de `?code=` del callback fallido: `missing_pending`, `invalid_state`, `access_denied`,
`invalid_request`, `provider_error`, `exchange_failed`, `provider_unavailable`, `internal`.
Muestra un mensaje generico segun el codigo; nunca llega texto del proveedor.

`/auth/me`:

```json
{
  "sub": "1b2c-3d4e",
  "email": "ana@example.com",
  "name": "Ana Perez",
  "groups": ["ventas"],
  "attributes": { "custom:tenant_id": "t-42" }
}
```

`email` y `name` pueden ser `null`; `attributes` solo trae los claims de `EXPOSED_CLAIMS`.

### Cuenta y MFA

Todas requieren sesion (`401 unauthenticated` si no) y los `POST` el header CSRF.

| Ruta | Metodo | Cuerpo | Respuesta |
|---|---|---|---|
| `/auth/account/mfa` | GET | | `200 {"totp": "enabled" \| "disabled"}` |
| `/auth/account/mfa/totp/associate` | POST | | `200 {"secret": "..."}`; arma el QR (`otpauth://`) con el email de `/auth/me` |
| `/auth/account/mfa/totp/verify` | POST | `{"code": "123456", "deviceName": "Telefono"}` (`deviceName` opcional) | `204` |
| `/auth/account/mfa/preference` | POST | `{"totp": true}` | `204` |
| `/auth/account/change-password` | POST | `{"previousPassword": "...", "proposedPassword": "..."}` | `204` |

Errores propios de cuenta (siempre con el sobre de abajo):

| Codigo | Estado | Cuando |
|---|---|---|
| `code_mismatch` | 400 | El codigo TOTP no coincide |
| `code_expired` | 400 | El codigo TOTP vencio |
| `mfa_setup_invalid` | 400 | No hay una asociacion de TOTP pendiente o es invalida |
| `invalid_password` | 400 | La contrasena propuesta no cumple la politica |
| `not_authorized` | 400 | La contrasena anterior es incorrecta |
| `too_many_requests` | 429 | Cognito limito los intentos; espera antes de reintentar |

`not_authorized` es `400`, no `401`: no cierra la sesion ni dispara el login.

### Proxy `/api/*`

`ANY /api/<ruta>?<query>` se reenvia a `UPSTREAM_BASE_URL/<ruta>?<query>` con el access token del
usuario. Status y cuerpo del upstream llegan tal cual (incluidos sus propios `4xx`/`5xx`);
`Set-Cookie` se elimina. Las rutas con `..`, `\`, `%2e`, `%2f` o similares se rechazan con
`400`. Cuerpo maximo `PROXY_MAX_BODY_BYTES` (1 MiB por defecto) -> `413`.

### Sobre de error

Todo error generado por el BFF (no los del upstream) es:

```json
{ "error": "unauthenticated", "requestId": "Zx3k9A2qIAMEJ6w=" }
```

`requestId` coincide con la cabecera `X-Request-ID`, presente en todas las respuestas; muestralo
al usuario o mandalo a tu logging.

| Estado | `error` | Que hacer |
|---|---|---|
| 400 | `bad_request` | Bug de la SPA (cuerpo o ruta invalidos) |
| 400 | `code_mismatch`, `code_expired`, `not_authorized`, `invalid_password`, `mfa_setup_invalid` | Mensaje al usuario (ver cuenta) |
| 401 | `unauthenticated` | Llamar a `login()`; el BFF ya borro la cookie |
| 403 | `csrf` | Falta el header CSRF o el origen no coincide (seccion 3) |
| 403 | `forbidden` | Sin permiso |
| 404, 405, 415 | `not_found`, `method_not_allowed`, `unsupported_media_type` | Bug de la SPA |
| 413 | `payload_too_large` | Cuerpo sobre el limite |
| 429 | `too_many_requests` | Reintentar mas tarde |
| 500 | `internal` | Reportar con `requestId` |
| 502, 504 | `upstream_unavailable`, `upstream_timeout` | Tu API no respondio; reintentar |
| 503 | `busy` | No se pudo refrescar la sesion a tiempo; respeta `Retry-After: 1` y reintenta |

## 3. CSRF

Toda peticion `POST`, `PUT`, `PATCH` o `DELETE` a `/auth/*` y `/api/*` necesita:

1. La cabecera configurada en `CSRF_HEADER_NAME` (por defecto `X-Requested-With`), **una sola
   vez**, con cualquier valor (incluso vacio). Una cabecera repetida cuenta como ausente.
2. Si el navegador manda `Sec-Fetch-Site`, debe ser `same-origin` o `none`.
3. Si manda `Origin`, debe ser exactamente `PUBLIC_ORIGIN`.

Si falla: `403 {"error":"csrf"}`, y se evalua antes de mirar la sesion. Los navegadores ponen
`Sec-Fetch-Site` y `Origin` solos; la SPA solo agrega la cabecera. Los `GET` no la necesitan.
Como `X-Requested-With` no es una cabecera "simple", un formulario o una pagina ajena no pueden
mandarla sin un preflight de CORS que el BFF no concede.

## 4. Cliente TypeScript

Sin dependencias ni framework; compila con `tsc --strict`. Copia y adapta.

- `bootstrap()` al arrancar: devuelve el usuario o `null` (anonimo). Decide tu si llamas a
  `login()` de inmediato o muestras una pantalla publica.
- `request()` agrega `credentials: 'include'` y el header CSRF en metodos inseguros. Ante un
  `401` redirige a `/auth/login` con la ruta actual como `returnTo` y deja la promesa
  pendiente (la pagina se va a descargar).
- `api()` es el atajo para JSON hacia `/api/*`; lanza `BffError` con `status`, `code` y
  `requestId`.
- `openSocket()` pide un boleto nuevo por cada conexion (ver seccion 6).

```ts
export interface User {
  sub: string;
  email: string | null;
  name: string | null;
  groups: string[];
  attributes: Record<string, unknown>;
}

export class BffError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly requestId: string | null,
  ) {
    super(`${status} ${code}`);
  }
}

const CSRF = { 'X-Requested-With': 'fetch' };
const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export function login(): void {
  const returnTo = location.pathname + location.search;
  location.assign('/auth/login?returnTo=' + encodeURIComponent(returnTo));
}

async function toError(r: Response): Promise<BffError> {
  let code = 'unknown';
  let requestId = r.headers.get('X-Request-ID');
  try {
    const b = (await r.json()) as { error?: string; requestId?: string };
    code = b.error ?? code;
    requestId = b.requestId ?? requestId;
  } catch {
    // cuerpo que no es del BFF (p. ej. un error del upstream)
  }
  return new BffError(r.status, code, requestId);
}

export async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const method = (init.method ?? 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  if (UNSAFE.has(method)) for (const [k, v] of Object.entries(CSRF)) headers.set(k, v);
  const r = await fetch(path, { ...init, method, headers, credentials: 'include' });
  if (r.status === 401) {
    login();
    return new Promise<Response>(() => {});
  }
  return r;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (typeof init.body === 'string' && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const r = await request('/api/' + path.replace(/^\/+/, ''), { ...init, headers });
  if (!r.ok) throw await toError(r);
  return r.status === 204 ? (undefined as T) : ((await r.json()) as T);
}

export async function bootstrap(): Promise<User | null> {
  const r = await fetch('/auth/me', { credentials: 'include' });
  if (r.status === 401) return null;
  if (!r.ok) throw await toError(r);
  return (await r.json()) as User;
}

export async function logout(): Promise<void> {
  const r = await fetch('/auth/logout', { method: 'POST', headers: CSRF, credentials: 'include' });
  if (!r.ok) throw await toError(r);
  const { logoutUrl } = (await r.json()) as { logoutUrl: string };
  location.assign(logoutUrl);
}

/** `appProtocol`: el subprotocolo de tu app (p. ej. `app.v1`); el boleto va segundo. */
export async function openSocket(url: string, appProtocol: string): Promise<WebSocket> {
  const r = await request('/auth/ws-ticket', { method: 'POST' });
  if (!r.ok) throw await toError(r);
  const { ticket } = (await r.json()) as { ticket: string; expiresIn: number };
  return new WebSocket(url, [appProtocol, ticket]);
}
```

Uso:

```ts
const user = await bootstrap();          // null = anonimo
if (!user) login();

const pedidos = await api<Pedido[]>('pedidos?estado=abierto');
await api('pedidos', { method: 'POST', body: JSON.stringify({ sku: 'A-1' }) });

try {
  await api('pedidos/999');
} catch (e) {
  if (e instanceof BffError) console.warn(e.code, e.requestId);
}

// Un boleto nuevo en cada conexion y reconexion: es de un solo uso.
const ws = await openSocket('wss://ws.example.com', 'app.v1');
ws.onmessage = (m) => console.log(m.data);
```

El `WebSocket` lo atiende **tu** servidor, no el BFF: el BFF solo emite el boleto
(`WSTICKET#<hash>`, un solo uso, ligado a la sesion y al perfil) y tu servidor lo canjea
(consume el boleto de forma atomica; ver `WsTicketStore` en [architecture.md](architecture.md)). El helper manda `[<subprotocolo de tu app>, ticket]` en `Sec-WebSocket-Protocol`; tu servidor
reconoce el boleto (43 caracteres base64url, sin puntos: no se confunde con un JWT), lo
canjea y responde eligiendo el subprotocolo de la app, nunca el boleto. Conviene que, en cada
mensaje o cada pocos minutos, revise que la sesion `SESSION#<session_hash>` siga existiendo
(leyendo solo `pk` y `ttl`) para cortar la conexion tras un logout.

## 5. Migrar desde una SPA con tokens en el navegador

Para una SPA tipo `oidc-client-ts`, `amazon-cognito-identity-js` o Amplify Auth:

- **Borra** la libreria OIDC, el `UserManager`, la pagina de callback de la SPA, el renovador
  silencioso (iframe o refresh en JS), el interceptor que agregaba `Authorization: Bearer` y
  todo lo que guarde tokens en `localStorage`, `sessionStorage` o IndexedDB. Limpia tambien las
  claves viejas de los usuarios existentes al primer arranque.
- **Reemplaza** "obtener token" por `credentials: 'include'`, y las llamadas a tu API
  (`https://api.example.com/x`) por `/api/x`. La API ya no necesita CORS para la SPA.
- **Login**: `location.assign('/auth/login?returnTo=...')`. El callback de Cognito ahora es
  `https://app.example.com/auth/callback` (registralo en el app client) y no una ruta de la SPA.
- **Logout**: `POST /auth/logout` y luego `location.assign(logoutUrl)`. El BFF ya borro la
  sesion y revoco el refresh token; la URL cierra ademas la sesion del Hosted UI de Cognito y
  regresa a `LOGOUT_REDIRECT_PATH`. Ese destino debe estar en los *sign-out URLs* del app client.
- **Perfil y permisos**: `email`, `name`, `groups` y los claims extra salen de `/auth/me`, ya
  no de decodificar el ID token. Anade claims con `EXPOSED_CLAIMS`.
- **CSP `connect-src`**: la SPA solo habla con su propio origen, asi que `connect-src 'self'`
  basta (es el valor por defecto del modulo `cloudfront`). Quita el dominio de Cognito y el de
  tu API; si abres WebSockets agrega solo el origen `wss://` correspondiente. `form-action
  'self'` y `frame-ancestors 'none'` tambien aplican.
- **Enrutador de la SPA**: no captures `/auth/*` ni `/api/*` en el fallback a `index.html`; la
  CloudFront Function del modulo ya los manda al BFF.
- **Desarrollo local**: proxy de `/auth` y `/api` hacia el BFF (ver README), para que sea el
  mismo origen.

## 6. Trampas

- **Cookies de terceros (Safari y otros).** ITP y las politicas de cookies de terceros bloquean
  o purgan cookies entre sitios. Si el BFF viviera en `api.otro-dominio.com` y la SPA en
  `app.example.com`, la cookie `SameSite=Lax` no se mandaria en `fetch`/XHR. Por eso todo va por
  el mismo origen detras de CloudFront, y por eso `__Host-` exige `Path=/` y no admite `Domain`.
  No muevas el BFF a otro sitio.
- **El boleto nunca va en la URL.** Las URLs terminan en logs de acceso, historial, `Referer` y
  herramientas de monitoreo. Va en `Sec-WebSocket-Protocol` (segundo subprotocolo), no en
  `?ticket=`.
- **Boleto de un solo uso y 30 s** (`WS_TICKET_TTL_SECS`, maximo 120). Pide uno nuevo para
  *cada* conexion, incluida cada reconexion, y abre el socket enseguida; no lo guardes ni lo
  reutilices. Un boleto gastado o vencido hace fallar el handshake en tu servidor.
- **No hagas login con `fetch`.** `/auth/login` responde `303` hacia otro dominio; hay que
  navegar con `location.assign`.
- **`401` en `/auth/me` no es un error.** No redirijas en un bucle: en la pagina de login o en
  la pantalla publica, usa `bootstrap()` y no `request()`.
- **Sesion multi-pestana.** El logout en una pestana invalida la cookie en todas; la siguiente
  llamada de las otras dara `401` y el cliente redirigira al login.
- **Respuestas del upstream.** Un `401` que viene de tu API (no del BFF) tambien se trata como
  sesion invalida en `request()`; si tu API usa `401` con otro significado, cambia esa regla.
- **Sin `custom_error_response` en CloudFront.** Si agregas uno, los `401/403/404` del BFF se
  vuelven `200` con HTML y la SPA deja de ver el sobre de error.
