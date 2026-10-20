output "state_bucket_name" {
  description = "Bucket del estado."
  value       = aws_s3_bucket.state.id
}

output "state_bucket_arn" {
  description = "ARN del bucket del estado."
  value       = aws_s3_bucket.state.arn
}

output "kms_key_arn" {
  description = "Llave KMS para `key_provider \"aws_kms\"` en los envs."
  value       = aws_kms_key.state.arn
}

output "kms_alias" {
  description = "Alias de la llave KMS."
  value       = aws_kms_alias.state.name
}

output "github_oidc_provider_arn" {
  description = "Proveedor OIDC de GitHub usado por los roles."
  value       = local.github_oidc_provider_arn
}

output "deploy_role_arns" {
  description = "ARN de cada rol `gh-deploy-<env>`."
  value       = { for env, role in aws_iam_role.deploy : env => role.arn }
}

output "lambda_boundary_policy_arns" {
  description = "ARN del techo de permisos por ambiente: se pasa como `permissions_boundary_arn` al modulo `bff`."
  value       = local.boundary_arns
}
