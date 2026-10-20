output "api_endpoint" {
  description = "URL de la HTTP API (origen de CloudFront)."
  value       = aws_apigatewayv2_api.bff.api_endpoint
}

output "api_domain" {
  description = "Host de la HTTP API, sin esquema."
  value       = replace(aws_apigatewayv2_api.bff.api_endpoint, "https://", "")
}

output "table_name" {
  description = "Tabla de sesiones."
  value       = aws_dynamodb_table.sessions.name
}

output "table_arn" {
  description = "ARN de la tabla de sesiones."
  value       = aws_dynamodb_table.sessions.arn
}

output "origin_verify_secret_arn" {
  description = "Secreto de X-Origin-Verify (null si esta desactivado)."
  value       = var.origin_verify_enabled ? aws_secretsmanager_secret.origin_verify[0].arn : null
}

output "lambda_function_name" {
  description = "Nombre de la Lambda."
  value       = aws_lambda_function.bff.function_name
}

output "lambda_role_arn" {
  description = "Rol de la Lambda."
  value       = aws_iam_role.lambda.arn
}

output "client_id" {
  description = "App client que usa el BFF."
  value       = local.client_id
}
