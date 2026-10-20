terraform {
  required_version = ">= 1.12.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0, < 7.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.7.0, < 4.0.0"
    }
  }

  # El client secret y el secreto de X-Origin-Verify quedan en el estado: el cifrado es
  # obligatorio (PLAN §11.2). Con `enforced = true` OpenTofu se niega a escribir sin cifrar.
  #
  # backend "s3" {
  #   bucket       = "<state_bucket_name del bootstrap>"
  #   key          = "envs/dev/terraform.tfstate"
  #   region       = "us-east-2"
  #   use_lockfile = true
  #   encrypt      = true
  # }
  #
  # encryption {
  #   key_provider "aws_kms" "estado" {
  #     kms_key_id = "alias/cognito-bff-state"
  #     key_spec   = "AES_256"
  #     region     = "us-east-2"
  #   }
  #
  #   method "aes_gcm" "estado" {
  #     keys = key_provider.aws_kms.estado
  #   }
  #
  #   state {
  #     method   = method.aes_gcm.estado
  #     enforced = true
  #   }
  #
  #   plan {
  #     method   = method.aes_gcm.estado
  #     enforced = true
  #   }
  # }
}
