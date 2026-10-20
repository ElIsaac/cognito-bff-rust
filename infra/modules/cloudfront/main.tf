locals {
  # `<project>-<env>`: el rol gh-deploy-<env> solo toca distribuciones con estas etiquetas.
  name_parts = split("-", var.name)
  env        = coalesce(var.env, length(local.name_parts) > 1 ? element(local.name_parts, length(local.name_parts) - 1) : "default")
  project    = coalesce(var.project, length(local.name_parts) > 1 ? join("-", slice(local.name_parts, 0, length(local.name_parts) - 1)) : var.name)
  tags       = merge(var.tags, { Project = local.project, Env = local.env })

  s3_origin_id  = "spa"
  bff_origin_id = "bff"

  # IDs de las politicas administradas de CloudFront.
  cache_policy_optimized_id     = "658327ea-f89d-4fab-a63d-7e88639e58f6" # CachingOptimized
  cache_policy_disabled_id      = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" # CachingDisabled
  origin_request_all_no_host_id = "b689b0a8-53d0-40ab-baf2-68738e2966ac" # AllViewerExceptHostHeader
  origin_verify_enabled         = var.origin_verify_enabled != null ? var.origin_verify_enabled : var.origin_verify_secret_arn != null
  origin_verify_value           = local.origin_verify_enabled ? data.aws_secretsmanager_secret_version.origin_verify[0].secret_string : null
  bff_paths                     = ["/auth/*", "/api/*"]
  has_certificate               = var.acm_certificate_arn != null
  hsts_max_age_secs             = 31536000
  all_methods                   = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
  read_methods                  = ["GET", "HEAD"]
}

# ---------------------------------------------------------------------------------------
# Secreto de X-Origin-Verify (§7.3). Su valor queda en el estado: cifrarlo es obligatorio.
# ---------------------------------------------------------------------------------------

data "aws_secretsmanager_secret_version" "origin_verify" {
  count = local.origin_verify_enabled ? 1 : 0

  secret_id = var.origin_verify_secret_arn
}

# ---------------------------------------------------------------------------------------
# Origen S3 con OAC y fallback de la SPA (decision 51: sin custom_error_response)
# ---------------------------------------------------------------------------------------

resource "aws_cloudfront_origin_access_control" "spa" {
  name                              = "${var.name}-spa"
  description                       = "OAC del bucket de la SPA."
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_function" "spa" {
  name    = "${var.name}-spa"
  comment = "Fallback de la SPA: rutas sin extension sirven /index.html."
  runtime = "cloudfront-js-2.0"
  publish = true
  code    = file("${path.module}/functions/spa.js")
}

# ---------------------------------------------------------------------------------------
# Cabeceras de seguridad (decision 8)
# ---------------------------------------------------------------------------------------

resource "aws_cloudfront_response_headers_policy" "security" {
  name    = "${var.name}-security"
  comment = "HSTS, nosniff, Referrer-Policy, frame-options y CSP."

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = local.hsts_max_age_secs
      include_subdomains         = true
      preload                    = false
      override                   = true
    }

    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    content_security_policy {
      content_security_policy = var.csp
      override                = true
    }
  }
}

# ---------------------------------------------------------------------------------------
# Distribucion
# ---------------------------------------------------------------------------------------

resource "aws_cloudfront_distribution" "this" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = var.name
  default_root_object = "index.html"
  aliases             = var.aliases
  price_class         = var.price_class
  web_acl_id          = var.web_acl_arn
  http_version        = "http2and3"
  tags                = local.tags

  origin {
    origin_id                = local.s3_origin_id
    domain_name              = var.spa_bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.spa.id
  }

  origin {
    origin_id   = local.bff_origin_id
    domain_name = var.bff_api_domain

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    dynamic "custom_header" {
      for_each = local.origin_verify_enabled ? [local.origin_verify_value] : []
      content {
        name  = "X-Origin-Verify"
        value = custom_header.value
      }
    }
  }

  default_cache_behavior {
    target_origin_id           = local.s3_origin_id
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = local.read_methods
    cached_methods             = local.read_methods
    compress                   = true
    cache_policy_id            = local.cache_policy_optimized_id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa.arn
    }
  }

  dynamic "ordered_cache_behavior" {
    for_each = local.bff_paths
    content {
      path_pattern               = ordered_cache_behavior.value
      target_origin_id           = local.bff_origin_id
      viewer_protocol_policy     = "https-only"
      allowed_methods            = local.all_methods
      cached_methods             = local.read_methods
      compress                   = true
      cache_policy_id            = local.cache_policy_disabled_id
      origin_request_policy_id   = local.origin_request_all_no_host_id
      response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = local.has_certificate ? null : true
    acm_certificate_arn            = var.acm_certificate_arn
    ssl_support_method             = local.has_certificate ? "sni-only" : null
    minimum_protocol_version       = local.has_certificate ? "TLSv1.2_2021" : null
  }

  dynamic "logging_config" {
    for_each = var.logging_bucket == null ? [] : [var.logging_bucket]
    content {
      bucket          = logging_config.value
      prefix          = var.name
      include_cookies = false
    }
  }

  lifecycle {
    precondition {
      condition     = length(var.aliases) == 0 || local.has_certificate
      error_message = "Con `aliases` hace falta `acm_certificate_arn` (us-east-1)."
    }
  }
}

# ---------------------------------------------------------------------------------------
# Bucket policy: solo este OAC puede leer la SPA
# ---------------------------------------------------------------------------------------

data "aws_iam_policy_document" "spa_bucket" {
  count = var.create_spa_bucket_policy ? 1 : 0

  statement {
    sid       = "LecturaDesdeCloudFront"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${var.spa_bucket_name}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.this.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "spa" {
  count = var.create_spa_bucket_policy ? 1 : 0

  bucket = var.spa_bucket_name
  policy = data.aws_iam_policy_document.spa_bucket[0].json
}
