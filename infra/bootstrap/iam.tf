# ---------------------------------------------------------------------------------------
# Permisos de los roles gh-deploy-<env>
#
# Cuatro politicas administradas por ambiente (cada una por debajo del tope de 6144
# caracteres): estado, servicios de datos/computo, red/CloudFront e IAM (con techo). Lo que IAM permite
# acotar por nombre se acota por `<project>-<env>*` y por region; lo demas queda como
# comodin de recurso con la razon anotada.
# ---------------------------------------------------------------------------------------

locals {
  region_account = "${var.region}:${local.account_id}"
  user_pool_arns = length(var.cognito_user_pool_arns) > 0 ? var.cognito_user_pool_arns : ["arn:aws:cognito-idp:${local.region_account}:userpool/*"]
}

# --- Estado -----------------------------------------------------------------------------

data "aws_iam_policy_document" "state_access" {
  for_each = local.envs

  statement {
    sid       = "ListarEstado"
    actions   = ["s3:ListBucket", "s3:GetBucketVersioning"]
    resources = [aws_s3_bucket.state.arn]
  }

  statement {
    sid       = "EstadoDelAmbiente"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/envs/${each.key}/*"]
  }

  statement {
    sid       = "LlaveDelEstado"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.state.arn]
  }
}

# --- Datos y computo del modulo bff -----------------------------------------------------

data "aws_iam_policy_document" "bff_services" {
  for_each = local.envs

  statement {
    sid = "Sesiones"
    actions = [
      "dynamodb:CreateTable",
      "dynamodb:DeleteTable",
      "dynamodb:UpdateTable",
      "dynamodb:DescribeTable",
      "dynamodb:DescribeContinuousBackups",
      "dynamodb:UpdateContinuousBackups",
      "dynamodb:DescribeTimeToLive",
      "dynamodb:UpdateTimeToLive",
      "dynamodb:DescribeContributorInsights",
      "dynamodb:DescribeKinesisStreamingDestination",
      "dynamodb:ListTagsOfResource",
      "dynamodb:TagResource",
      "dynamodb:UntagResource",
    ]
    resources = ["arn:aws:dynamodb:${local.region_account}:table/${var.project}-${each.key}*"]
  }

  statement {
    sid = "Lambda"
    actions = [
      "lambda:CreateFunction",
      "lambda:DeleteFunction",
      "lambda:GetFunction",
      "lambda:GetFunctionConfiguration",
      "lambda:GetFunctionCodeSigningConfig",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
      "lambda:ListVersionsByFunction",
      "lambda:PutFunctionConcurrency",
      "lambda:DeleteFunctionConcurrency",
      "lambda:AddPermission",
      "lambda:RemovePermission",
      "lambda:GetPolicy",
      "lambda:ListTags",
      "lambda:TagResource",
      "lambda:UntagResource",
    ]
    resources = ["arn:aws:lambda:${local.region_account}:function:${var.project}-${each.key}*"]
  }

  statement {
    sid = "Secretos"
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:DeleteSecret",
      "secretsmanager:DescribeSecret",
      "secretsmanager:UpdateSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:GetSecretValue",
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:TagResource",
      "secretsmanager:UntagResource",
    ]
    resources = ["arn:aws:secretsmanager:${local.region_account}:secret:${var.project}-${each.key}*"]
  }

  statement {
    sid = "ParametrosSsm"
    actions = [
      "ssm:PutParameter",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:DeleteParameter",
      "ssm:AddTagsToResource",
      "ssm:RemoveTagsFromResource",
      "ssm:ListTagsForResource",
    ]
    resources = ["arn:aws:ssm:${local.region_account}:parameter/${var.project}/${each.key}/*"]
  }

  # DescribeParameters no admite recurso.
  statement {
    sid       = "ListarParametrosSsm"
    actions   = ["ssm:DescribeParameters"]
    resources = ["*"]
  }

  # El nombre del client no esta en el ARN (lleva el ID del pool): se acota por pool.
  statement {
    sid = "AppClientDelBff"
    actions = [
      "cognito-idp:CreateUserPoolClient",
      "cognito-idp:UpdateUserPoolClient",
      "cognito-idp:DeleteUserPoolClient",
      "cognito-idp:DescribeUserPoolClient",
      "cognito-idp:DescribeUserPool",
    ]
    resources = local.user_pool_arns
  }
}

# --- Red, IAM, logs y CloudFront --------------------------------------------------------

data "aws_iam_policy_document" "bff_network" {
  for_each = local.envs

  # API Gateway v2 no admite nombres en el ARN: se acota a las HTTP APIs de la region.
  statement {
    sid     = "HttpApi"
    actions = ["apigateway:GET", "apigateway:POST", "apigateway:PUT", "apigateway:PATCH", "apigateway:DELETE"]
    resources = [
      "arn:aws:apigateway:${var.region}::/apis",
      "arn:aws:apigateway:${var.region}::/apis/*",
      "arn:aws:apigateway:${var.region}::/tags/*",
    ]
  }

  statement {
    sid = "GruposDeLogs"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:PutRetentionPolicy",
      "logs:DeleteRetentionPolicy",
      "logs:TagResource",
      "logs:UntagResource",
      "logs:ListTagsForResource",
    ]
    resources = [
      "arn:aws:logs:${local.region_account}:log-group:/aws/lambda/${var.project}-${each.key}*",
      "arn:aws:logs:${local.region_account}:log-group:/aws/lambda/${var.project}-${each.key}*:*",
      "arn:aws:logs:${local.region_account}:log-group:/aws/apigateway/${var.project}-${each.key}*",
      "arn:aws:logs:${local.region_account}:log-group:/aws/apigateway/${var.project}-${each.key}*:*",
    ]
  }

  # Estas acciones no admiten recurso; el stage con access log las usa para crear la entrega.
  statement {
    sid = "EntregaDeLogs"
    actions = [
      "logs:DescribeLogGroups",
      "logs:DescribeResourcePolicies",
      "logs:PutResourcePolicy",
      "logs:CreateLogDelivery",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
    ]
    resources = ["*"]
  }

  # El ID de la distribucion y de las politicas no existe hasta crearlas: no se pueden acotar
  # por nombre. Solo la funcion lleva el prefijo.
  statement {
    sid = "CloudFront"
    actions = [
      "cloudfront:CreateDistribution",
      "cloudfront:CreateDistributionWithTags",
      "cloudfront:UpdateDistribution",
      "cloudfront:DeleteDistribution",
      "cloudfront:GetDistribution",
      "cloudfront:TagResource",
      "cloudfront:UntagResource",
      "cloudfront:ListTagsForResource",
      "cloudfront:CreateOriginAccessControl",
      "cloudfront:GetOriginAccessControl",
      "cloudfront:UpdateOriginAccessControl",
      "cloudfront:DeleteOriginAccessControl",
      "cloudfront:CreateResponseHeadersPolicy",
      "cloudfront:GetResponseHeadersPolicy",
      "cloudfront:UpdateResponseHeadersPolicy",
      "cloudfront:DeleteResponseHeadersPolicy",
    ]
    resources = [
      "arn:aws:cloudfront::${local.account_id}:distribution/*",
      "arn:aws:cloudfront::${local.account_id}:origin-access-control/*",
      "arn:aws:cloudfront::${local.account_id}:response-headers-policy/*",
    ]
  }

  statement {
    sid = "FuncionDeCloudFront"
    actions = [
      "cloudfront:CreateFunction",
      "cloudfront:DescribeFunction",
      "cloudfront:GetFunction",
      "cloudfront:UpdateFunction",
      "cloudfront:PublishFunction",
      "cloudfront:DeleteFunction",
    ]
    resources = ["arn:aws:cloudfront::${local.account_id}:function/${var.project}-${each.key}*"]
  }

  # Las acciones de creacion y de listado de CloudFront no admiten recurso.
  statement {
    sid = "ListadosDeCloudFront"
    actions = [
      "cloudfront:ListDistributions",
      "cloudfront:ListOriginAccessControls",
      "cloudfront:ListResponseHeadersPolicies",
      "cloudfront:ListFunctions",
    ]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(var.spa_bucket_arns) > 0 ? [var.spa_bucket_arns] : []
    content {
      sid       = "PolicyDelBucketDeLaSpa"
      actions   = ["s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"]
      resources = statement.value
    }
  }
}

# --- IAM: roles de la Lambda con techo obligatorio ---------------------------------------
#
# Sin techo, quien asume `gh-deploy-<env>` podria crear un rol `<project>-<env>-x` con
# `AdministratorAccess` y asumirlo (escalada de privilegios). Con el techo:
#   - Allow: crear roles y ponerles politicas solo si el rol queda con el techo del env.
#   - Deny: lo mismo al reves (si falta el techo o es otro), mas quitar el techo y tocar la
#     politica del techo. El Deny gana aunque otra politica permita la accion.
# Los permisos efectivos de un rol creado son la interseccion de su politica y el techo.

locals {
  boundary_arns = { for env in var.envs : env => aws_iam_policy.lambda_boundary[env].arn }
}

data "aws_iam_policy_document" "bff_iam" {
  for_each = local.envs

  # No ensanchan permisos: no necesitan condicion.
  statement {
    sid = "RolDeLaLambdaLectura"
    actions = [
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:UpdateRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:GetRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
      "iam:TagRole",
      "iam:UntagRole",
    ]
    resources = ["arn:aws:iam::${local.account_id}:role/${var.project}-${each.key}*"]
  }

  statement {
    sid = "RolDeLaLambdaConTecho"
    actions = [
      "iam:CreateRole",
      "iam:PutRolePolicy",
      "iam:PutRolePermissionsBoundary",
    ]
    resources = ["arn:aws:iam::${local.account_id}:role/${var.project}-${each.key}*"]

    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [local.boundary_arns[each.key]]
    }
  }

  statement {
    sid       = "PasarElRolALambda"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.account_id}:role/${var.project}-${each.key}*"]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }

  statement {
    sid    = "SinTechoNoHayRol"
    effect = "Deny"
    actions = [
      "iam:CreateRole",
      "iam:PutRolePolicy",
      "iam:AttachRolePolicy",
      "iam:PutRolePermissionsBoundary",
    ]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "iam:PermissionsBoundary"
      values   = [local.boundary_arns[each.key]]
    }
  }

  statement {
    sid       = "NoQuitarElTecho"
    effect    = "Deny"
    actions   = ["iam:DeleteRolePermissionsBoundary"]
    resources = ["*"]
  }

  statement {
    sid    = "NoTocarLaPoliticaDelTecho"
    effect = "Deny"
    actions = [
      "iam:CreatePolicyVersion",
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:SetDefaultPolicyVersion",
    ]
    resources = [local.boundary_arns[each.key]]
  }
}

# Techo de los roles de la Lambda: lo que el BFF necesita y nada mas.
data "aws_iam_policy_document" "lambda_boundary" {
  for_each = local.envs

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${local.region_account}:log-group:/aws/lambda/${var.project}-${each.key}*:*"]
  }

  statement {
    sid = "Sesiones"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
    ]
    resources = concat(
      ["arn:aws:dynamodb:${local.region_account}:table/${var.project}-${each.key}*"],
      var.lambda_extra_table_arns,
    )
  }

  statement {
    sid       = "Secretos"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = concat(["arn:aws:secretsmanager:${local.region_account}:secret:${var.project}-${each.key}*"], var.lambda_extra_secret_arns)
  }

  dynamic "statement" {
    for_each = length(var.lambda_kms_key_arns) > 0 ? [var.lambda_kms_key_arns] : []
    content {
      sid       = "LlaveDeLaTabla"
      actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      resources = statement.value
    }
  }
}

resource "aws_iam_policy" "lambda_boundary" {
  for_each = local.envs

  name        = "${var.project}-${each.key}-lambda-boundary"
  description = "Techo de permisos de los roles de la Lambda de ${var.project}-${each.key}."
  policy      = data.aws_iam_policy_document.lambda_boundary[each.key].json
}

# --- Politicas y adjuntos ---------------------------------------------------------------

locals {
  deploy_policies = {
    for pair in setproduct(var.envs, ["state-access", "bff-services", "bff-network", "bff-iam"]) :
    "${pair[0]}/${pair[1]}" => {
      env  = pair[0]
      tipo = pair[1]
    }
  }
  deploy_policy_json = {
    "state-access" = data.aws_iam_policy_document.state_access
    "bff-services" = data.aws_iam_policy_document.bff_services
    "bff-network"  = data.aws_iam_policy_document.bff_network
    "bff-iam"      = data.aws_iam_policy_document.bff_iam
  }
}

resource "aws_iam_policy" "deploy" {
  for_each = local.deploy_policies

  name        = "gh-deploy-${each.value.env}-${each.value.tipo}"
  description = "Permisos de gh-deploy-${each.value.env} (${each.value.tipo})."
  policy      = local.deploy_policy_json[each.value.tipo][each.value.env].json
}

resource "aws_iam_role_policy_attachment" "deploy" {
  for_each = local.deploy_policies

  role       = aws_iam_role.deploy[each.value.env].name
  policy_arn = aws_iam_policy.deploy[each.key].arn
}
