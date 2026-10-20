data "aws_caller_identity" "current" {}

locals {
  client_id         = var.create_app_client ? aws_cognito_user_pool_client.bff[0].id : var.cognito_client_id
  client_secret_arn = var.create_app_client ? aws_secretsmanager_secret.client[0].arn : var.client_secret_arn
  secret_arns = compact([
    local.client_secret_arn,
    var.origin_verify_enabled ? aws_secretsmanager_secret.origin_verify[0].arn : "",
  ])
  log_group_name = "/aws/lambda/${var.name}"
  table_name     = coalesce(var.table_name, "${var.name}-sessions")
  callback_url   = "${var.public_origin}/auth/callback"
}

# ---------------------------------------------------------------------------------------
# Tabla de sesiones, logins en curso y boletos WS (§5)
# ---------------------------------------------------------------------------------------

resource "aws_dynamodb_table" "sessions" {
  name                        = local.table_name
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  deletion_protection_enabled = var.dynamodb_deletion_protection
  tags                        = var.tags

  attribute {
    name = "pk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.dynamodb_kms_key_arn
  }
}

# ---------------------------------------------------------------------------------------
# App client confidencial (opcional, decision 6)
# ---------------------------------------------------------------------------------------

resource "aws_cognito_user_pool_client" "bff" {
  count = var.create_app_client ? 1 : 0

  name                                 = var.name
  user_pool_id                         = var.cognito_user_pool_id
  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = split(" ", var.oidc_scopes)
  callback_urls                        = concat([local.callback_url], var.extra_callback_urls)
  logout_urls                          = ["${var.public_origin}${var.logout_redirect_path}"]
  supported_identity_providers         = ["COGNITO"]
  explicit_auth_flows                  = ["ALLOW_USER_SRP_AUTH"]
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
  access_token_validity                = 15
  id_token_validity                    = 15
  refresh_token_validity               = ceil(var.session_absolute_ttl_secs / 86400)

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  refresh_token_rotation {
    feature                    = "ENABLED"
    retry_grace_period_seconds = 10
  }
}

resource "aws_secretsmanager_secret" "client" {
  count = var.create_app_client ? 1 : 0

  name_prefix = "${var.name}/cognito-client-secret-"
  description = "Client secret del app client del BFF (lo escribe OpenTofu; el estado va cifrado)."
  tags        = var.tags
}

resource "aws_secretsmanager_secret_version" "client" {
  count = var.create_app_client ? 1 : 0

  secret_id     = aws_secretsmanager_secret.client[0].id
  secret_string = aws_cognito_user_pool_client.bff[0].client_secret
}

# ---------------------------------------------------------------------------------------
# Secreto de X-Origin-Verify (§7.3)
# ---------------------------------------------------------------------------------------

resource "random_password" "origin_verify" {
  count = var.origin_verify_enabled ? 1 : 0

  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "origin_verify" {
  count = var.origin_verify_enabled ? 1 : 0

  name_prefix = "${var.name}/origin-verify-"
  description = "Cabecera X-Origin-Verify que CloudFront agrega hacia el BFF."
  tags        = var.tags
}

resource "aws_secretsmanager_secret_version" "origin_verify" {
  count = var.origin_verify_enabled ? 1 : 0

  secret_id     = aws_secretsmanager_secret.origin_verify[0].id
  secret_string = random_password.origin_verify[0].result
}

# ---------------------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "lambda" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name                 = "${var.name}-lambda"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.tags
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid = "Sesiones"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
    ]
    resources = [aws_dynamodb_table.sessions.arn]
  }

  statement {
    sid       = "Secretos"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = local.secret_arns
  }

  dynamic "statement" {
    for_each = var.dynamodb_kms_key_arn == null ? [] : [var.dynamodb_kms_key_arn]
    content {
      sid       = "LlaveTabla"
      actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${var.name}-lambda"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "bff" {
  function_name                  = var.name
  description                    = "BFF de Cognito (cognito-bff-rust)."
  role                           = aws_iam_role.lambda.arn
  runtime                        = "provided.al2023"
  architectures                  = ["arm64"]
  handler                        = "bootstrap"
  filename                       = var.lambda_zip_path
  source_code_hash               = filebase64sha256(var.lambda_zip_path)
  memory_size                    = var.lambda_memory_mb
  timeout                        = var.lambda_timeout_secs
  reserved_concurrent_executions = var.lambda_reserved_concurrency
  tags                           = var.tags

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.lambda.name
  }

  environment {
    variables = {
      PUBLIC_ORIGIN             = var.public_origin
      COGNITO_ISSUER            = var.cognito_issuer
      COGNITO_DOMAIN            = var.cognito_domain
      COGNITO_CLIENT_ID         = local.client_id
      COGNITO_CLIENT_SECRET_ARN = local.client_secret_arn
      OIDC_SCOPES               = var.oidc_scopes
      EXPOSED_CLAIMS            = join(",", var.exposed_claims)
      SESSIONS_TABLE            = aws_dynamodb_table.sessions.name
      UPSTREAM_BASE_URL         = var.upstream_base_url
      ORIGIN_VERIFY_SECRET_ARN  = var.origin_verify_enabled ? aws_secretsmanager_secret.origin_verify[0].arn : ""
      SESSION_ABSOLUTE_TTL_SECS = tostring(var.session_absolute_ttl_secs)
      SESSION_IDLE_TTL_SECS     = tostring(var.session_idle_ttl_secs)
      REFRESH_LEASE_SECS        = tostring(var.refresh_lease_secs)
      IDP_TIMEOUT_SECS          = tostring(var.idp_timeout_secs)
      PROXY_MAX_BODY_BYTES      = tostring(var.proxy_max_body_bytes)
      PROXY_TIMEOUT_SECS        = tostring(var.proxy_timeout_secs)
      LOGOUT_REDIRECT_PATH      = var.logout_redirect_path
      AUTH_ERROR_REDIRECT_PATH  = var.auth_error_redirect_path
      RUST_LOG                  = var.log_level
    }
  }

  lifecycle {
    precondition {
      condition     = var.create_app_client ? var.cognito_user_pool_id != null : (var.cognito_client_id != null && var.client_secret_arn != null)
      error_message = "Con create_app_client = true hace falta cognito_user_pool_id; si no, cognito_client_id y client_secret_arn."
    }
    precondition {
      condition     = var.idp_timeout_secs < var.refresh_lease_secs
      error_message = "idp_timeout_secs debe ser menor que refresh_lease_secs (decision 42)."
    }
  }

  depends_on = [aws_iam_role_policy.lambda]
}

# ---------------------------------------------------------------------------------------
# API Gateway HTTP API: solo se usa como origen de CloudFront
# ---------------------------------------------------------------------------------------

resource "aws_apigatewayv2_api" "bff" {
  name          = var.name
  protocol_type = "HTTP"
  description   = "Origen del BFF detras de CloudFront."
  tags          = var.tags
}

resource "aws_apigatewayv2_integration" "bff" {
  api_id                 = aws_apigatewayv2_api.bff.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.bff.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = min(var.lambda_timeout_secs * 1000, 30000)
}

resource "aws_apigatewayv2_route" "default" {
  api_id    = aws_apigatewayv2_api.bff.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.bff.id}"
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigateway/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.bff.id
  name        = "$default"
  auto_deploy = true
  tags        = var.tags

  default_route_settings {
    throttling_rate_limit  = var.api_throttle_rate
    throttling_burst_limit = var.api_throttle_burst
  }

  # Sin query ni cabeceras: pueden llevar `code` o `state`.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format = jsonencode({
      requestId          = "$context.requestId"
      ip                 = "$context.identity.sourceIp"
      method             = "$context.httpMethod"
      path               = "$context.path"
      status             = "$context.status"
      responseLength     = "$context.responseLength"
      integrationLatency = "$context.integrationLatency"
      integrationError   = "$context.integrationErrorMessage"
    })
  }
}

resource "aws_lambda_permission" "api" {
  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.bff.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.bff.execution_arn}/*/*"
}

# ---------------------------------------------------------------------------------------
# Salidas para otros estados (opcional)
# ---------------------------------------------------------------------------------------

locals {
  ssm_values = var.ssm_prefix == null ? {} : merge(
    {
      "api-domain" = replace(aws_apigatewayv2_api.bff.api_endpoint, "https://", "")
      "table-name" = aws_dynamodb_table.sessions.name
      "table-arn"  = aws_dynamodb_table.sessions.arn
    },
    var.origin_verify_enabled ? { "origin-verify-secret-arn" = aws_secretsmanager_secret.origin_verify[0].arn } : {},
  )
}

resource "aws_ssm_parameter" "out" {
  for_each = local.ssm_values

  name  = "${var.ssm_prefix}/${each.key}"
  type  = "String"
  value = each.value
  tags  = var.tags
}
