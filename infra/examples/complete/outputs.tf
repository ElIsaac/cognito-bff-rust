output "distribution_id" {
  description = "ID de la distribucion (para invalidar cache al publicar la SPA)."
  value       = module.cloudfront.distribution_id
}

output "cloudfront_domain_name" {
  description = "Destino del CNAME del dominio publico."
  value       = module.cloudfront.domain_name
}

output "bff_client_id" {
  description = "App client creado para el BFF."
  value       = module.bff.client_id
}

output "bff_api_domain" {
  description = "Origen del BFF detras de CloudFront."
  value       = module.bff.api_domain
}
