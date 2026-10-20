# bootstrap

Raiz que se corre **una sola vez**, en local y con credenciales de administrador, para crear lo
que necesitan los demas estados (PLAN §11.1, decision 4):

- Bucket S3 del estado: versionado, SSE-S3, sin acceso publico, solo TLS, versiones antiguas
  con expiracion y `prevent_destroy`.
- Llave KMS (rotacion anual) con alias, para el cifrado cliente del estado.
- Proveedor OIDC de GitHub (solo si `create_github_oidc_provider = true`).
- Roles `gh-deploy-<env>` con confianza en `repo:OWNER/REPO:environment:<env>-plan` y
  `repo:OWNER/REPO:environment:<env>` (decision 3) y permisos acotados por prefijo
  `<project>-<env>*` y region donde IAM lo permite.
- Una *permissions boundary* por ambiente (`<project>-<env>-lambda-boundary`) que todo rol
  creado por `gh-deploy-<env>` debe llevar (ver "Techo de permisos").

## Un proveedor OIDC por cuenta

AWS solo admite un proveedor `token.actions.githubusercontent.com` por cuenta. Si ya existe,
deja `create_github_oidc_provider = false` y pasa su ARN en `existing_github_oidc_provider_arn`.
Pasar los dos (o ninguno) falla con un mensaje claro.

## Primera vez, paso a paso

1. Copia y rellena las variables:

   ```sh
   cd infra/bootstrap
   cp terraform.tfvars.example terraform.tfvars
   ```

   Ajusta `github_owner`, `github_repo`, `region`, `state_bucket_name` y el proveedor OIDC.

2. Genera la passphrase del estado local y guardala en el gestor de contrasenas (sin ella no
   se puede leer el estado de este directorio):

   ```sh
   export TF_VAR_bootstrap_passphrase=$(openssl rand -base64 32)
   ```

   `versions.tf` cifra el estado con `key_provider "pbkdf2"` y esa passphrase. El estado es
   local mientras no exista la llave KMS.

3. Crea todo con credenciales locales (un perfil de administrador, solo para este paso):

   ```sh
   tofu init
   tofu apply
   ```

4. Con la llave KMS ya creada, edita `versions.tf`: reemplaza el bloque `encryption` por el
   comentado al final (metodo `aws_kms` con la passphrase como `fallback`) y descomenta el
   `backend "s3"` (`bucket` = salida `state_bucket_name`, `key = "bootstrap/terraform.tfstate"`,
   `use_lockfile = true`). Los valores son literales: `backend` y `encryption` no aceptan
   referencias a recursos.

5. Migra el estado y reescribelo con el metodo nuevo:

   ```sh
   tofu init -migrate-state
   tofu apply        # sin cambios; reescribe el estado cifrado con KMS
   ```

   Despues puedes retirar el `fallback` y dejar de usar la passphrase.

6. Borra el estado local y comprueba que no queda nada versionable:

   ```sh
   rm -f terraform.tfstate terraform.tfstate.*
   git status --short   # no debe listar terraform.tfstate*
   ```

## Techo de permisos (cierra la escalada de privilegios)

Los roles `gh-deploy-<env>` deben poder crear el rol de la Lambda y ponerle una politica
inline. Sin mas control, quien asuma el rol de deploy (un workflow comprometido, un PR
malicioso aprobado) podria crear `<project>-<env>-x` con `AdministratorAccess` y asumirlo. Lo
que lo impide:

1. El bootstrap crea la politica administrada `<project>-<env>-lambda-boundary` (techo) con lo
   unico que necesita la Lambda del BFF: `logs:CreateLogStream` y `PutLogEvents` en sus log
   groups, `dynamodb:GetItem/PutItem/UpdateItem/DeleteItem` en las tablas
   `<project>-<env>*`, `secretsmanager:GetSecretValue` en los secretos `<project>-<env>*` y,
   si lo configuras, KMS sobre `lambda_kms_key_arns`. Tablas o secretos fuera del prefijo
   (un `table_name` propio, un `client_secret_arn` creado a mano) se agregan con
   `lambda_extra_table_arns` y `lambda_extra_secret_arns`; si no, el techo los niega.
2. `iam:CreateRole`, `iam:PutRolePolicy` y `iam:PutRolePermissionsBoundary` solo se permiten con
   `iam:PermissionsBoundary` igual al ARN del techo; un `Deny` explicito repite la regla
   (tambien para `iam:AttachRolePolicy`), de modo que ninguna otra politica la abra.
3. `iam:DeleteRolePermissionsBoundary` esta negado, y tambien `CreatePolicyVersion`,
   `DeletePolicy`, `DeletePolicyVersion` y `SetDefaultPolicyVersion` sobre el techo.

Los permisos efectivos de un rol con techo son la interseccion de su politica y el techo:
aunque el deploy ponga una politica con `*`, el rol no sale de lo anterior.

Orden al adoptarlo en una cuenta que ya tiene el rol de la Lambda sin techo: aplica el bootstrap
(crea los techos y la politica nueva `bff-iam`), y despues aplica el env con
`permissions_boundary_arn` puesto. El modulo `bff` actualiza el techo del rol antes que su
politica, que es el orden que aceptan los roles `gh-deploy`. Con `permissions_boundary_arn =
null` (el valor por omision) el modulo se comporta como antes, pero un rol `gh-deploy` ya no
podra crearlo.

El techo y las politicas de deploy son politicas administradas distintas del rol de la Lambda:
`gh-deploy-<env>` no tiene ninguna accion IAM sobre politicas, solo sobre roles.

## Despues del bootstrap

- En el repo de envs crea los GitHub environments `<env>` y `<env>-plan` y limita los
  *deployment branches* a `main`.
- Cada env usa el bucket y la llave: `backend "s3"` con `key = "envs/<env>/terraform.tfstate"`
  (el rol solo escribe bajo `envs/<env>/*`) y `key_provider "aws_kms"` con el alias de la
  salida `kms_alias`.
- Pasa la salida `lambda_boundary_policy_arns` (la del ambiente) como `permissions_boundary_arn`
  al modulo `bff`: sin ella, `gh-deploy-<env>` no puede crear ni modificar el rol de la
  Lambda (ver "Techo de permisos").
- Los permisos de CloudFront y API Gateway no admiten nombres en el ARN: quedan acotados por
  tipo de recurso y region, no por prefijo.

## Variables y salidas

Ver `variables.tf` y `outputs.tf`. Salidas: `state_bucket_name`, `state_bucket_arn`,
`kms_key_arn`, `kms_alias`, `github_oidc_provider_arn`, `deploy_role_arns` y
`lambda_boundary_policy_arns` (por ambiente).
