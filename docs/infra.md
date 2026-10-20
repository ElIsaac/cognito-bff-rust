# Infraestructura (OpenTofu)

Todo vive en `infra/`. El repo publico no contiene instancias ni valores reales: solo modulos,
un bootstrap y un ejemplo. Las instancias (`envs/dev`, `envs/prod`) van en un repo privado.

| Ruta | Para que sirve |
|---|---|
| `infra/modules/bff` | Lambda, HTTP API, tabla de sesiones, secretos, app client opcional |
| `infra/modules/cloudfront` | Distribucion completa: SPA en S3 y BFF detras |
| `infra/bootstrap` | Se corre una vez: bucket de estado, llave KMS, OIDC de GitHub y roles de deploy |
| `infra/examples/complete` | Composicion de `bff` y `cloudfront` con valores de ejemplo |

Requisitos: OpenTofu `>= 1.12.0`, proveedor `aws >= 6.0.0, < 7.0.0` y `random >= 3.7.0, < 4.0.0`.

## Aviso: hay secretos en el estado

- Con `create_app_client = true` el **client secret** de Cognito pasa por el estado
  (`aws_cognito_user_pool_client.client_secret` y `aws_secretsmanager_secret_version`).
- El secreto de **X-Origin-Verify** (`random_password`) tambien queda en el estado, y el modulo
  `cloudfront` lo lee con un data source para ponerlo como cabecera de origen.

Por eso el cifrado del estado es obligatorio en todos los envs: bloque `encryption` con
`key_provider "aws_kms"` y `enforced = true` tanto en `state` como en `plan` (ver
`infra/examples/complete/versions.tf`). Con `enforced = true` OpenTofu se niega a escribir
estado o plan sin cifrar. Si no quieres el secreto en el estado, usa `create_app_client = false`
y pasa `client_secret_arn` de un secreto creado a mano.

## Modulo `bff`

Ver `infra/modules/bff/variables.tf` para la lista completa. Las entradas principales:
`name`, `lambda_zip_path`, `public_origin`, `cognito_issuer`, `cognito_domain`,
`upstream_base_url`, `create_app_client` (con `cognito_user_pool_id`) o `cognito_client_id` y
`client_secret_arn`, `extra_callback_urls`, los TTL y `origin_verify_enabled`.

Salidas usadas por `cloudfront`: `api_domain` y `origin_verify_secret_arn`. Tambien expone
`api_endpoint`, `table_name`, `table_arn`, `lambda_function_name`, `lambda_role_arn` y `client_id`.

## Modulo `cloudfront`

Para quien no tiene una distribucion: crea todo lo necesario para servir una SPA de S3 y el BFF
en el mismo origen (cookies `__Host-`, sin CORS).

Crea:

- OAC para S3 y, por omision, la bucket policy que le da `s3:GetObject`.
- Behavior por omision a S3 con `CachingOptimized` y una CloudFront Function (`cloudfront-js-2.0`,
  viewer-request) que reescribe a `/index.html` toda ruta cuyo ultimo segmento no lleva `.`.
  No hay `custom_error_response`: aplicaria a todos los behaviors y convertiria los 401, 403 y
  404 del BFF en un 200 con HTML (decision 51).
- Behaviors `/auth/*` y `/api/*` hacia el BFF: `CachingDisabled`,
  `AllViewerExceptHostHeader`, todos los metodos, `https-only` hacia el visitante y el origen,
  TLSv1.2 y la cabecera `X-Origin-Verify`.
- Response headers policy: HSTS de 1 ano con `includeSubDomains`, `nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, `X-Frame-Options: DENY` y la CSP.
- `minimum_protocol_version = TLSv1.2_2021` cuando hay certificado.

### Entradas

| Variable | Descripcion |
|---|---|
| `name` | Prefijo de los recursos |
| `aliases` | Dominios (lista, puede ser vacia; con alias hace falta certificado) |
| `acm_certificate_arn` | Certificado en us-east-1; `null` usa el de CloudFront |
| `spa_bucket_name`, `spa_bucket_regional_domain_name` | Bucket de la SPA |
| `create_spa_bucket_policy` | Crear la bucket policy del OAC (por omision `true`) |
| `bff_api_domain` | Salida `api_domain` del modulo `bff` |
| `origin_verify_secret_arn` | Salida `origin_verify_secret_arn` de `bff`; `null` = sin cabecera |
| `origin_verify_enabled` | Opcional. Ponlo en `true` cuando el ARN viene de un recurso aun no creado |
| `csp` | Content-Security-Policy; el valor por omision solo admite el mismo origen |
| `price_class` | Por omision `PriceClass_100` |
| `web_acl_arn` | WAFv2 (scope CLOUDFRONT), opcional |
| `logging_bucket` | Bucket de logs de acceso (`<bucket>.s3.amazonaws.com`), opcional |
| `tags` | Etiquetas |

### Salidas

`distribution_id`, `distribution_arn`, `domain_name`, `hosted_zone_id`.

### Notas

- El plan no puede saber si un ARN que sale de un recurso nuevo sera `null`; por eso, al componer
  con `bff`, pasa `origin_verify_enabled = true` y `depends_on = [module.bff]` (la version del
  secreto debe existir antes de leerla). El ejemplo lo hace.
- Si el bucket ya tiene una bucket policy, pon `create_spa_bucket_policy = false` y agrega a mano
  el permiso `s3:GetObject` para `cloudfront.amazonaws.com` con
  `AWS:SourceArn = distribution_arn`.
- La funcion tiene pruebas sin dependencias: `node --test infra/modules/cloudfront/functions/*.test.mjs`.
- El DNS (Route 53, Cloudflare) no lo maneja el modulo: apunta el dominio a `domain_name`.

## `bootstrap`

Se corre una vez, en local y con credenciales de administrador. Crea el bucket del estado, la
llave KMS, el proveedor OIDC de GitHub (opcional, solo hay uno por cuenta) y los roles
`gh-deploy-<env>`. La guia paso a paso, incluida la migracion del estado de `pbkdf2` a KMS, esta
en `infra/bootstrap/README.md`.

## Como usan los modulos los repos de envs

El repo privado de envs no copia los modulos: los referencia por commit, de modo que un cambio
del repo publico nunca llega a un env sin una revision.

```hcl
module "bff" {
  source = "git::https://github.com/ElIsaac/cognito-bff-rust.git//infra/modules/bff?ref=<sha-de-40-caracteres>"
  # ...
}

module "cloudfront" {
  source = "git::https://github.com/ElIsaac/cognito-bff-rust.git//infra/modules/cloudfront?ref=<sha-de-40-caracteres>"
  # ...
}
```

- Fija siempre el SHA completo (no una rama ni un tag movil). Actualizar es cambiar el `ref`,
  correr `tofu init -upgrade` y revisar el `plan`.
- Cada env versiona su `.terraform.lock.hcl`; los modulos no fijan proveedores.
- Cada env usa su `backend "s3"` (`key = "envs/<env>/terraform.tfstate"`, `use_lockfile = true`) y
  el bloque `encryption` con `aws_kms` y `enforced = true`.
- El CI de PR corre `tofu fmt -check -recursive`, `tofu validate`, `tflint` y `trivy config` sin
  credenciales de AWS; `plan` y `apply` usan los roles `gh-deploy-<env>` (environments
  `<env>-plan` y `<env>`).
