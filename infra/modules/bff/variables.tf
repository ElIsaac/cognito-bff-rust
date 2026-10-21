variable "name" {
  description = "Prefijo de todos los recursos (p. ej. `cognito-bff-dev`)."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,40}$", var.name))
    error_message = "Solo minusculas, digitos y guiones (3 a 41 caracteres)."
  }
}

variable "lambda_zip_path" {
  description = "Zip de `cargo lambda build --release --arm64 --output-format zip -p lambda`."
  type        = string
}

variable "public_origin" {
  description = "Origen publico del front y del BFF, sin barra final (`https://app.example.com`)."
  type        = string

  validation {
    condition     = can(regex("^https://[a-z0-9.-]+(:[0-9]+)?$", var.public_origin))
    error_message = "Debe ser https://host[:puerto] sin ruta."
  }
}

variable "cognito_issuer" {
  description = "`https://cognito-idp.<region>.amazonaws.com/<poolId>`."
  type        = string
}

variable "cognito_domain" {
  description = "Dominio del Hosted UI / Managed Login con `https://`."
  type        = string
}

variable "create_app_client" {
  description = "Crear el app client confidencial y su secreto. Si es false, se pasan `cognito_client_id` y `client_secret_arn`."
  type        = bool
  default     = false
}

variable "cognito_user_pool_id" {
  description = "Solo con `create_app_client = true`."
  type        = string
  default     = null
}

variable "cognito_client_id" {
  description = "Client existente (con `create_app_client = false`)."
  type        = string
  default     = null
}

variable "client_secret_arn" {
  description = "ARN del secreto con el client secret (con `create_app_client = false`)."
  type        = string
  default     = null
}

variable "extra_callback_urls" {
  description = "Callbacks extra del client creado (p. ej. `http://localhost:5173/auth/callback`)."
  type        = list(string)
  default     = []
}

variable "upstream_base_url" {
  description = "API a la que el BFF reenvia `/api/*`, sin barra final."
  type        = string
}

variable "upstream_auth" {
  description = "Como se autentica el BFF ante el upstream: `none` (`Authorization: Bearer <access>`) o `aws_iam` (Function URL con `AuthType: AWS_IAM`: SigV4 y access token en `upstream_token_header`)."
  type        = string
  default     = "none"

  validation {
    condition     = contains(["none", "aws_iam"], var.upstream_auth)
    error_message = "Debe ser `none` o `aws_iam`."
  }
}

variable "upstream_token_header" {
  description = "Cabecera que lleva el access token crudo con `upstream_auth = \"aws_iam\"`. Minusculas; no `authorization`, `host`, `cookie` ni `x-amz-*`."
  type        = string
  default     = "x-bff-access-token"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.upstream_token_header)) && !contains(["authorization", "host", "cookie"], var.upstream_token_header) && !startswith(var.upstream_token_header, "x-amz-")
    error_message = "Minusculas, digitos y guiones; no `authorization`, `host`, `cookie` ni `x-amz-*`."
  }
}

variable "upstream_lambda_function_arn" {
  description = "ARN de la Lambda cuya Function URL (`AWS_IAM`) es el upstream. Obligatorio con `upstream_auth = \"aws_iam\"`: se concede `lambda:InvokeFunctionUrl` y `lambda:InvokeFunction` sobre ella."
  type        = string
  default     = null

  validation {
    condition     = var.upstream_auth != "aws_iam" || var.upstream_lambda_function_arn != null
    error_message = "`upstream_lambda_function_arn` es obligatorio con `upstream_auth = \"aws_iam\"`."
  }
}

variable "exposed_claims" {
  description = "Claims extra del ID token que salen en `/auth/me` y en el boleto WS."
  type        = list(string)
  default     = []
}

variable "oidc_scopes" {
  description = "Scopes pedidos a Cognito."
  type        = string
  default     = "openid email profile"
}

variable "session_absolute_ttl_secs" {
  description = "Vida absoluta de la sesion; no mayor que la validez del refresh token."
  type        = number
  default     = 2592000
}

variable "session_idle_ttl_secs" {
  description = "Inactividad maxima."
  type        = number
  default     = 43200
}

variable "refresh_lease_secs" {
  description = "Duracion del lease de refresh."
  type        = number
  default     = 10
}

variable "idp_timeout_secs" {
  description = "Timeout HTTP hacia Cognito; menor que `refresh_lease_secs`."
  type        = number
  default     = 4
}

variable "proxy_max_body_bytes" {
  description = "Tope del body reenviado (tope duro 5 MiB en el codigo)."
  type        = number
  default     = 1048576
}

variable "proxy_timeout_secs" {
  description = "Timeout total del upstream."
  type        = number
  default     = 10
}

variable "logout_redirect_path" {
  description = "Ruta local a la que vuelve Cognito tras el logout."
  type        = string
  default     = "/"
}

variable "auth_error_redirect_path" {
  description = "Ruta local a la que va un login fallido (`?code=`)."
  type        = string
  default     = "/"
}

variable "origin_verify_enabled" {
  description = "Exigir `X-Origin-Verify` (secreto que CloudFront agrega como cabecera de origen)."
  type        = bool
  default     = true
}

variable "lambda_memory_mb" {
  description = "Memoria de la Lambda."
  type        = number
  default     = 512
}

variable "lambda_timeout_secs" {
  description = "Timeout de la Lambda (el BFF recibe `REQUEST_BUDGET_SECS` = este valor menos 1). Debe superar `proxy_timeout_secs + idp_timeout_secs + 5`; el maximo util es 30 s (tope de integracion de API Gateway)."
  type        = number
  default     = 20
}

variable "lambda_reserved_concurrency" {
  description = "Concurrencia reservada (-1 = sin reserva)."
  type        = number
  default     = -1
}

variable "origin_verify_previous_grace_secs" {
  description = "Cuanto vale el valor anterior (`AWSPREVIOUS`) de `X-Origin-Verify` desde que el BFF ve el actual; cubre la propagacion de CloudFront tras rotar."
  type        = number
  default     = 900
}

variable "log_level" {
  description = "`RUST_LOG` de la Lambda."
  type        = string
  default     = "info"
}

variable "log_retention_days" {
  description = "Retencion de los logs de la Lambda y de API Gateway."
  type        = number
  default     = 30
}

variable "api_throttle_rate" {
  description = "Peticiones por segundo del stage."
  type        = number
  default     = 50
}

variable "api_throttle_burst" {
  description = "Rafaga del stage."
  type        = number
  default     = 100
}

variable "table_name" {
  description = "Nombre de la tabla de sesiones; null usa `<name>-sessions`. Util si un techo de permisos del consumidor del boleto WS solo admite ciertos prefijos."
  type        = string
  default     = null
}

variable "dynamodb_kms_key_arn" {
  description = "Llave KMS propia para la tabla; null usa la de AWS."
  type        = string
  default     = null
}

variable "dynamodb_deletion_protection" {
  description = "Proteccion contra borrado de la tabla de sesiones."
  type        = bool
  default     = true
}

variable "ssm_prefix" {
  description = "Si se da (p. ej. `/cognito-bff/dev`), publica dominio de la API, secreto de origen, tabla y rol de la Lambda en SSM para otros estados."
  type        = string
  default     = null
}

variable "permissions_boundary_arn" {
  description = "Techo de permisos (permissions boundary) del rol de la Lambda; null = sin techo. Los roles `gh-deploy-<env>` de `infra/bootstrap` exigen el techo que ese bootstrap crea (salida `lambda_boundary_policy_arns`)."
  type        = string
  default     = null
}

variable "project" {
  description = "Valor de la etiqueta `Project`, con la que los roles `gh-deploy-<env>` acotan sus permisos (debe coincidir con `project` de `infra/bootstrap`). Null = `name` sin su ultimo segmento (`cognito-bff` para `cognito-bff-dev`)."
  type        = string
  default     = null
}

variable "env" {
  description = "Valor de la etiqueta `Env` (uno de `envs` de `infra/bootstrap`). Null = ultimo segmento de `name` (`dev` para `cognito-bff-dev`)."
  type        = string
  default     = null
}

variable "tags" {
  description = "Etiquetas de todos los recursos; `Project` y `Env` se agregan siempre."
  type        = map(string)
  default     = {}
}
