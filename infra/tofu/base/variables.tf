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

variable "aurora_engine_version" {
  description = "Aurora PostgreSQL engine version. Target is PG18 (A0-1). If us-east-1 does not offer it yet, set the newest supported major (for example 17.5) and record the fallback in progress.md."
  type        = string
  default     = "18.6"
}

variable "aurora_max_acu" {
  description = "Aurora Serverless v2 maximum capacity in ACU. Minimum is fixed at 0 (auto-pause)."
  type        = number
  default     = 1
}

variable "aurora_seconds_until_auto_pause" {
  description = "Idle seconds before Aurora pauses (300 to 86400)."
  type        = number
  default     = 300
}

variable "checkpoint_retention_days" {
  description = "Object Lock governance default retention for the checkpoints bucket."
  type        = number
  default     = 1
}

variable "cognito_domain_prefix" {
  description = "Cognito hosted domain prefix. Must be globally unique in the region; override if taken."
  type        = string
  default     = "locksmith-dev"
}

variable "web_callback_urls" {
  type    = list(string)
  default = ["http://localhost:3000/auth/callback"]
}

variable "web_logout_urls" {
  type    = list(string)
  default = ["http://localhost:3000/"]
}

variable "desktop_callback_urls" {
  type    = list(string)
  default = ["locksmith://auth/callback"]
}

variable "desktop_logout_urls" {
  type    = list(string)
  default = ["locksmith://auth/logout"]
}

variable "cli_callback_urls" {
  description = "Loopback redirect for the smith-cli authorization-code flow."
  type        = list(string)
  default     = ["http://127.0.0.1:53682/callback"]
}
