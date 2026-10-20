data "aws_s3_bucket" "spa" {
  bucket = var.spa_bucket_name
}

module "bff" {
  source = "../../modules/bff"

  name                 = var.name
  lambda_zip_path      = var.lambda_zip_path
  public_origin        = "https://${var.domain}"
  cognito_issuer       = "https://cognito-idp.${var.region}.amazonaws.com/${var.cognito_user_pool_id}"
  cognito_domain       = var.cognito_domain
  create_app_client    = true
  cognito_user_pool_id = var.cognito_user_pool_id
  extra_callback_urls  = var.extra_callback_urls
  upstream_base_url    = var.upstream_base_url
  tags                 = var.tags
}

module "cloudfront" {
  source = "../../modules/cloudfront"

  name                            = var.name
  aliases                         = [var.domain]
  acm_certificate_arn             = var.acm_certificate_arn
  spa_bucket_name                 = data.aws_s3_bucket.spa.id
  spa_bucket_regional_domain_name = data.aws_s3_bucket.spa.bucket_regional_domain_name
  bff_api_domain                  = module.bff.api_domain
  origin_verify_secret_arn        = module.bff.origin_verify_secret_arn
  csp                             = var.csp
  tags                            = var.tags

  # El plan no sabe si el ARN sera null, y el secreto debe tener su version escrita antes de
  # que CloudFront la lea.
  origin_verify_enabled = true
  depends_on            = [module.bff]
}
