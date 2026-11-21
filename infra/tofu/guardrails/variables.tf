variable "region" {
  description = "AWS region (decision A0-9). Also the only region the SCP allows."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Resource name prefix."
  type        = string
  default     = "locksmith-dev"
}

variable "alert_emails" {
  description = "Owner email addresses for the $1 and $3 Budget alerts and anomaly alerts. Supply at apply time (tfvars or -var); no address is committed."
  type        = list(string)
  validation {
    condition     = length(var.alert_emails) > 0 && alltrue([for e in var.alert_emails : can(regex("^[^@\\s]+@[^@\\s]+$", e))])
    error_message = "alert_emails needs at least one valid email address."
  }
}

variable "scp_target_id" {
  description = "Organizations root, OU or member account id (r-..., ou-..., 12 digits) the SCPs attach to. Use the dev member account or OU, never the management account."
  type        = string
}

variable "monthly_budget_usd" {
  description = "Monthly cost budget in USD (spec: 5)."
  type        = number
  default     = 5
}

variable "alert_thresholds_usd" {
  description = "Absolute actual-spend thresholds that send an email (spec: $1 and $3)."
  type        = list(number)
  default     = [1, 3]
}

variable "anomaly_threshold_usd" {
  description = "Minimum absolute anomaly impact in USD that triggers an email."
  type        = number
  default     = 1
}
