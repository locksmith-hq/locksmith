variable "region" {
  description = "AWS region (decision A0-9)."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Resource name prefix."
  type        = string
  default     = "locksmith-dev"
}

# Inputs below come from `tofu output -json` of the base stack (`just aws-up` passes them).
variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "session_tasks_security_group_id" { type = string }
variable "kms_key_arn" { type = string }
variable "ecr_repository_urls" {
  description = "Map of repository name to URL from the base stack."
  type        = map(string)
}
variable "aurora_endpoint" { type = string }
variable "cognito_issuer_url" { type = string }

variable "image_tag" {
  description = "Immutable ECR image tag for both services (for example a git SHA)."
  type        = string
}

variable "allowed_cidr" {
  description = "Your public IP as a /32. Only this range may reach the task ports; no default on purpose."
  type        = string
  validation {
    condition     = can(cidrhost(var.allowed_cidr, 0)) && var.allowed_cidr != "0.0.0.0/0"
    error_message = "allowed_cidr must be a valid CIDR and must not be 0.0.0.0/0."
  }
}

variable "database_url_parameter_arn" {
  description = "Optional SSM SecureString parameter ARN holding DATABASE_URL; injected by ECS, never in state or the task definition. Empty: the control plane starts without it."
  type        = string
  default     = ""
}

variable "session_hours" {
  description = "Auto-destroy timer: services are scaled to zero after this many hours."
  type        = number
  default     = 4
  validation {
    condition     = var.session_hours >= 1 && var.session_hours <= 12
    error_message = "session_hours must be between 1 and 12."
  }
}

variable "start_time" {
  description = "RFC3339 UTC time the session starts; the timer is computed from it. `just aws-up` sets it."
  type        = string
}
