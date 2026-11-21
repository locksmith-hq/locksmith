# Keyless CI apply (design decision 5, requirement "Keyless apply from CI").
# GitHub Actions assumes this role through OIDC; no AWS access key exists anywhere.
# The trust policy accepts exactly one subject: the approval environment of the
# `aws-base-apply` workflow in this repository (workflow_dispatch only). The role
# cannot touch Organizations, SCPs, Budgets, Cost Anomaly Detection or IAM
# (guardrails stay owner-applied in ../guardrails; see policies/*.tftpl).
variable "github_repo" {
  description = "GitHub repository (owner/name) allowed to assume the apply role. Exact match, never a wildcard."
  type        = string
  default     = "locksmith-hq/locksmith"
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repo))
    error_message = "github_repo must be exactly owner/name with no wildcard."
  }
}

variable "github_apply_environment" {
  description = "GitHub Actions environment (with required reviewers) the dispatched apply job runs in. The OIDC subject becomes repo:<github_repo>:environment:<this>. Restrict that environment to the main branch in GitHub."
  type        = string
  default     = "aws-base-apply"
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+$", var.github_apply_environment))
    error_message = "github_apply_environment must be a plain name with no wildcard."
  }
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "github_apply" {
  name                 = "${var.name}-github-apply"
  description          = "Assumed by the dispatched aws-base-apply workflow through GitHub OIDC."
  max_session_duration = 3600
  assume_role_policy = templatefile("${path.module}/policies/github-apply-trust.json.tftpl", {
    oidc_provider_arn  = aws_iam_openid_connect_provider.github.arn
    github_repo        = var.github_repo
    github_environment = var.github_apply_environment
  })
}

resource "aws_iam_role_policy" "github_apply" {
  name = "base-stack-apply"
  role = aws_iam_role.github_apply.id
  policy = templatefile("${path.module}/policies/github-apply-permissions.json.tftpl", {
    region = var.region
  })
}
