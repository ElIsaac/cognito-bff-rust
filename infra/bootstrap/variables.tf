variable "region" {
  description = "Region del bucket de estado, la llave KMS y los roles."
  type        = string
  default     = "us-east-2"
}

variable "project" {
  description = "Prefijo de los recursos del BFF (`<project>-<env>`); los permisos de los roles se acotan por este prefijo."
  type        = string
  default     = "cognito-bff"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.project))
    error_message = "Solo minusculas, digitos y guiones."
  }
}

variable "github_owner" {
  description = "Dueno de GitHub del repo que despliega (`ElIsaac`)."
  type        = string
}

variable "github_repo" {
  description = "Repo que despliega (el privado de envs)."
  type        = string
}

variable "envs" {
  description = "Ambientes; cada uno recibe un rol `gh-deploy-<env>` y un GitHub environment `<env>` y `<env>-plan`."
  type        = list(string)
  default     = ["dev", "prod"]

  validation {
    condition     = length(var.envs) > 0 && alltrue([for e in var.envs : can(regex("^[a-z][a-z0-9]{1,15}$", e))])
    error_message = "Cada ambiente: minusculas y digitos, 2 a 16 caracteres."
  }
}

variable "state_bucket_name" {
  description = "Nombre global del bucket de estado."
  type        = string
}

variable "kms_alias" {
  description = "Alias de la llave KMS del cifrado de estado (con prefijo `alias/`)."
  type        = string
  default     = "alias/cognito-bff-state"

  validation {
    condition     = startswith(var.kms_alias, "alias/")
    error_message = "Debe empezar con `alias/`."
  }
}

variable "create_github_oidc_provider" {
  description = "Crear el proveedor OIDC de GitHub. Solo puede haber uno por cuenta: si ya existe, deja false y pasa `existing_github_oidc_provider_arn`."
  type        = bool
  default     = false
}

variable "existing_github_oidc_provider_arn" {
  description = "ARN del proveedor OIDC de GitHub que ya existe (con `create_github_oidc_provider = false`)."
  type        = string
  default     = null
}

variable "noncurrent_version_days" {
  description = "Dias que se conservan las versiones antiguas del estado."
  type        = number
  default     = 90
}

variable "noncurrent_versions_kept" {
  description = "Versiones antiguas que se conservan aunque superen `noncurrent_version_days`."
  type        = number
  default     = 10
}

variable "spa_bucket_arns" {
  description = "Buckets de la SPA cuya bucket policy pueden escribir los roles (modulo `cloudfront`). Vacio = ninguno."
  type        = list(string)
  default     = []
}

variable "cognito_user_pool_arns" {
  description = "User pools donde los roles pueden crear el app client del BFF. Obligatorio: sin la lista, un rol de deploy podria tocar el app client de cualquier pool de la cuenta."
  type        = list(string)

  validation {
    condition     = length(var.cognito_user_pool_arns) > 0 && alltrue([for a in var.cognito_user_pool_arns : can(regex("^arn:aws[a-z-]*:cognito-idp:[a-z0-9-]+:[0-9]{12}:userpool/[A-Za-z0-9_-]+$", a))])
    error_message = "Al menos un ARN de user pool (`arn:aws:cognito-idp:<region>:<cuenta>:userpool/<id>`); sin comodines."
  }
}

variable "lambda_extra_table_arns" {
  description = "Tablas DynamoDB fuera del prefijo `<project>-<env>*` que la Lambda puede usar (p. ej. con `table_name` propio en el modulo `bff`). Entran al techo de los roles."
  type        = list(string)
  default     = []
}

variable "lambda_extra_secret_arns" {
  description = "Secretos fuera del prefijo `<project>-<env>*` que la Lambda puede leer (p. ej. un `client_secret_arn` creado a mano). Entran al techo de los roles."
  type        = list(string)
  default     = []
}

variable "lambda_kms_key_arns" {
  description = "Llaves KMS que la Lambda usa (`dynamodb_kms_key_arn` del modulo `bff`). Vacio = el techo no da permisos de KMS."
  type        = list(string)
  default     = []
}

variable "max_session_duration_secs" {
  description = "Duracion maxima de la sesion de los roles de deploy."
  type        = number
  default     = 3600
}

variable "bootstrap_passphrase" {
  description = "Passphrase (16 caracteres o mas) con la que se cifra el estado local de este directorio mientras no exista la llave KMS. Se pasa por `TF_VAR_bootstrap_passphrase`."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.bootstrap_passphrase) >= 16
    error_message = "La passphrase debe tener al menos 16 caracteres."
  }
}

variable "tags" {
  description = "Etiquetas de todos los recursos."
  type        = map(string)
  default     = {}
}
