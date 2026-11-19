# base root module: always-on dev resources (KMS, S3, ECR, network, Aurora, Cognito).
# Applied by the owner or the approved CI apply workflow; see README.md.
terraform {
  required_version = ">= 1.8.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
  }
  # State backend: bootstrap notes in README.md. `just aws-validate` runs with
  # -backend=false, so no backend block is declared until the bucket exists
  # (supply it with `tofu init -backend-config=...`).
}

provider "aws" {
  region = var.region
  default_tags {
    tags = local.tags
  }
}

locals {
  tags = {
    project = "locksmith"
    env     = "dev"
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
