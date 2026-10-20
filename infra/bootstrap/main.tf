data "aws_caller_identity" "current" {}

locals {
  account_id               = data.aws_caller_identity.current.account_id
  github_oidc_url          = "token.actions.githubusercontent.com"
  github_oidc_provider_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : var.existing_github_oidc_provider_arn
  repo_path                = "${var.github_owner}/${var.github_repo}"
  envs                     = toset(var.envs)
}

# ---------------------------------------------------------------------------------------
# Bucket del estado (§11.1)
# ---------------------------------------------------------------------------------------

resource "aws_s3_bucket" "state" {
  bucket = var.state_bucket_name

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3 a proposito: el contenido ya llega cifrado con KMS desde el cliente (bloque `encryption`).
#trivy:ignore:AVD-AWS-0132 el estado se cifra en el cliente con la llave KMS propia; SSE-S3 es solo la capa de reposo.
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "state_bucket" {
  statement {
    sid       = "SoloTLS"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.state]
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "versiones-antiguas"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days           = var.noncurrent_version_days
      newer_noncurrent_versions = var.noncurrent_versions_kept
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.state]
}

# ---------------------------------------------------------------------------------------
# Llave KMS del cifrado cliente del estado
# ---------------------------------------------------------------------------------------

resource "aws_kms_key" "state" {
  description             = "Cifrado cliente del estado de OpenTofu (${var.project})."
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "state" {
  name          = var.kms_alias
  target_key_id = aws_kms_key.state.key_id
}

# ---------------------------------------------------------------------------------------
# Proveedor OIDC de GitHub (uno por cuenta)
# ---------------------------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 1 : 0

  url            = "https://${local.github_oidc_url}"
  client_id_list = ["sts.amazonaws.com"]
}

# ---------------------------------------------------------------------------------------
# Roles gh-deploy-<env> (decision 3)
# ---------------------------------------------------------------------------------------

data "aws_iam_policy_document" "trust" {
  for_each = local.envs

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_url}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_url}:sub"
      values = [
        "repo:${local.repo_path}:environment:${each.key}-plan",
        "repo:${local.repo_path}:environment:${each.key}",
      ]
    }
  }
}

resource "aws_iam_role" "deploy" {
  for_each = local.envs

  name                 = "gh-deploy-${each.key}"
  description          = "Despliegue de ${var.project}-${each.key} desde GitHub Actions (OIDC)."
  assume_role_policy   = data.aws_iam_policy_document.trust[each.key].json
  max_session_duration = var.max_session_duration_secs

  lifecycle {
    precondition {
      condition     = var.create_github_oidc_provider != (var.existing_github_oidc_provider_arn != null)
      error_message = "Pasa exactamente uno: `create_github_oidc_provider = true` o `existing_github_oidc_provider_arn`."
    }
  }
}
