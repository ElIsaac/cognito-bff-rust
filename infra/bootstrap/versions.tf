terraform {
  required_version = ">= 1.12.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0, < 7.0.0"
    }
  }

  # Paso 2 de la guia (README): estado local cifrado con una passphrase (decision 4).
  # Rompe el ciclo "la llave KMS esta en el estado que quiero cifrar con esa llave".
  encryption {
    key_provider "pbkdf2" "bootstrap" {
      passphrase = var.bootstrap_passphrase
    }

    method "aes_gcm" "bootstrap" {
      keys = key_provider.pbkdf2.bootstrap
    }

    state {
      method   = method.aes_gcm.bootstrap
      enforced = true
    }

    plan {
      method   = method.aes_gcm.bootstrap
      enforced = true
    }
  }

  # Pasos 4 y 5 de la guia: con la llave KMS ya creada, reemplaza el bloque `encryption`
  # de arriba por este, agrega el backend y corre `tofu init -migrate-state`. Los valores
  # son literales: ni `backend` ni `encryption` aceptan referencias a recursos.
  # Retira el `fallback` y la passphrase cuando el estado ya se reescribio con KMS.
  #
  # backend "s3" {
  #   bucket       = "<state_bucket_name>"
  #   key          = "bootstrap/terraform.tfstate"
  #   region       = "us-east-2"
  #   use_lockfile = true
  #   encrypt      = true
  # }
  #
  # encryption {
  #   key_provider "pbkdf2" "bootstrap" {
  #     passphrase = var.bootstrap_passphrase
  #   }
  #
  #   method "aes_gcm" "bootstrap" {
  #     keys = key_provider.pbkdf2.bootstrap
  #   }
  #
  #   key_provider "aws_kms" "estado" {
  #     kms_key_id = "alias/cognito-bff-state"
  #     key_spec   = "AES_256"
  #     region     = "us-east-2"
  #   }
  #
  #   method "aes_gcm" "kms" {
  #     keys = key_provider.aws_kms.estado
  #   }
  #
  #   state {
  #     method   = method.aes_gcm.kms
  #     enforced = true
  #
  #     fallback {
  #       method = method.aes_gcm.bootstrap
  #     }
  #   }
  #
  #   plan {
  #     method   = method.aes_gcm.kms
  #     enforced = true
  #
  #     fallback {
  #       method = method.aes_gcm.bootstrap
  #     }
  #   }
  # }
}
