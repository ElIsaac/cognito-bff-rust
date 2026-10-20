variable "region" {
  description = "Region del BFF, la tabla y el bucket de la SPA."
  type        = string
  default     = "us-east-2"
}

variable "name" {
  description = "Prefijo de los recursos (p. ej. `cognito-bff-dev`)."
  type        = string
}

variable "domain" {
  description = "Dominio publico de la SPA y del BFF (`app.example.com`)."
  type        = string
}

variable "acm_certificate_arn" {
  description = "Certificado ACM de `domain` en us-east-1."
  type        = string
}

variable "spa_bucket_name" {
  description = "Bucket S3 existente de la SPA (privado)."
  type        = string
}

variable "cognito_user_pool_id" {
  description = "ID del User Pool existente."
  type        = string
}

variable "cognito_domain" {
  description = "Dominio del Hosted UI / Managed Login con `https://`."
  type        = string
}

variable "upstream_base_url" {
  description = "API a la que el BFF reenvia `/api/*`."
  type        = string
}

variable "lambda_zip_path" {
  description = "Zip de `cargo lambda build --release --arm64 --output-format zip -p lambda`."
  type        = string
}

variable "extra_callback_urls" {
  description = "Callbacks extra del app client (p. ej. localhost en dev)."
  type        = list(string)
  default     = []
}

variable "csp" {
  description = "Content-Security-Policy de la SPA. Ajustala a los recursos externos que cargue."
  type        = string
  default     = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
}

variable "permissions_boundary_arn" {
  description = "Techo de permisos del rol de la Lambda (salida `lambda_boundary_policy_arns` de `infra/bootstrap`). Obligatorio si despliegas con un rol `gh-deploy-<env>`."
  type        = string
  default     = null
}

variable "tags" {
  description = "Etiquetas de todos los recursos."
  type        = map(string)
  default     = {}
}
