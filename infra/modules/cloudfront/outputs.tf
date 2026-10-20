output "distribution_id" {
  description = "ID de la distribucion."
  value       = aws_cloudfront_distribution.this.id
}

output "distribution_arn" {
  description = "ARN de la distribucion."
  value       = aws_cloudfront_distribution.this.arn
}

output "domain_name" {
  description = "Dominio `*.cloudfront.net` (destino del CNAME o alias del DNS)."
  value       = aws_cloudfront_distribution.this.domain_name
}

output "hosted_zone_id" {
  description = "Zona hospedada de CloudFront, para registros alias de Route 53."
  value       = aws_cloudfront_distribution.this.hosted_zone_id
}
