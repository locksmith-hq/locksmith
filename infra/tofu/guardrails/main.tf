# guardrails root module: Budget, SCPs and Cost Anomaly Detection.
# Owner-applied from the Organizations MANAGEMENT account only. The CI apply role
# (../base/oidc.tf) is denied Organizations, Budgets and Cost Explorer, so it can
# never weaken these limits (design decision 6). SCPs do not restrict the
# management account itself, so they bind the member account(s) under target_id.
terraform {
  required_version = ">= 1.8.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
  }
}

# Budgets, Cost Explorer and Organizations are served from us-east-1 (A0-9).
provider "aws" {
  region = var.region
  default_tags {
    tags = {
      project = "locksmith"
      env     = "dev"
    }
  }
}

data "aws_partition" "current" {}
