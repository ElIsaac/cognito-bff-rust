variable "name" {
  description = "Prefijo de los recursos de la distribucion (p. ej. `cognito-bff-dev`)."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,40}$", var.name))
    error_message = "Solo minusculas, digitos y guiones (3 a 41 caracteres)."
  }
}

variable "aliases" {
  description = "Dominios de la distribucion (p. ej. `[\"app.example.com\"]`). Con alias hace falta `acm_certificate_arn`."
  type        = list(string)
  default     = []
}

variable "acm_certificate_arn" {
  description = "Certificado ACM en us-east-1. Null usa el certificado por omision de CloudFront (solo `*.cloudfront.net`)."
  type        = string
  default     = null
}

variable "spa_bucket_name" {
  description = "Bucket S3 con la SPA (privado, sin hosting de sitio web)."
  type        = string
}

variable "spa_bucket_regional_domain_name" {
  description = "Dominio regional del bucket de la SPA (`<bucket>.s3.<region>.amazonaws.com`)."
  type        = string
}

variable "create_spa_bucket_policy" {
  description = "Crear la bucket policy que da `s3:GetObject` al OAC de esta distribucion. Ponerlo en false si el bucket ya tiene una policy propia."
  type        = bool
  default     = true
}

variable "bff_api_domain" {
  description = "Host de la HTTP API del BFF, sin esquema (salida `api_domain` del modulo `bff`)."
  type        = string
}

variable "origin_verify_secret_arn" {
  description = "ARN del secreto de `X-Origin-Verify` (salida `origin_verify_secret_arn` del modulo `bff`). Null no agrega la cabecera."
  type        = string
  default     = null
}

variable "origin_verify_enabled" {
  description = "Si agregar la cabecera `X-Origin-Verify`. Null lo deduce de `origin_verify_secret_arn != null`; ponlo en true explicito cuando el ARN sale de un recurso que aun no existe (el plan no puede saber si es null)."
  type        = bool
  default     = null
}

variable "csp" {
  description = "Valor de `Content-Security-Policy`. El de omision solo admite recursos del mismo origen; amplialo para CDNs o fuentes externas."
  type        = string
  default     = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
}

variable "price_class" {
  description = "`PriceClass_100`, `PriceClass_200` o `PriceClass_All`."
  type        = string
  default     = "PriceClass_100"

  validation {
    condition     = contains(["PriceClass_100", "PriceClass_200", "PriceClass_All"], var.price_class)
    error_message = "Debe ser PriceClass_100, PriceClass_200 o PriceClass_All."
  }
}

variable "web_acl_arn" {
  description = "ARN de un WAFv2 web ACL (scope CLOUDFRONT, us-east-1). Opcional."
  type        = string
  default     = null
}

variable "logging_bucket" {
  description = "Bucket para los logs de acceso, como dominio (`<bucket>.s3.amazonaws.com`). Opcional; el bucket debe permitir ACLs."
  type        = string
  default     = null
}

variable "tags" {
  description = "Etiquetas de todos los recursos que las admiten."
  type        = map(string)
  default     = {}
}
