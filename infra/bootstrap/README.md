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

## Despues del bootstrap

- En el repo de envs crea los GitHub environments `<env>` y `<env>-plan` y limita los
  *deployment branches* a `main`.
- Cada env usa el bucket y la llave: `backend "s3"` con `key = "envs/<env>/terraform.tfstate"`
  (el rol solo escribe bajo `envs/<env>/*`) y `key_provider "aws_kms"` con el alias de la
  salida `kms_alias`.
- Los roles pueden crear roles con el prefijo `<project>-<env>*`; si quieres cerrar eso del
  todo, agrega una permissions boundary en una politica propia.
- Los permisos de CloudFront y API Gateway no admiten nombres en el ARN: quedan acotados por
  tipo de recurso y region, no por prefijo.

## Variables y salidas

Ver `variables.tf` y `outputs.tf`. Salidas: `state_bucket_name`, `state_bucket_arn`,
`kms_key_arn`, `kms_alias`, `github_oidc_provider_arn`, `deploy_role_arns`.
