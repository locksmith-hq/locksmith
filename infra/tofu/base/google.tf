# Google sign-in with a closed email list. The Google IdP exists only once a client id is
# supplied (TF_VAR_google_client_id / TF_VAR_google_client_secret at apply time, never committed).
# The allowlist Lambda is what keeps everyone else out: see lambda/presignup.py.
variable "google_client_id" {
  type    = string
  default = ""
}

variable "google_client_secret" {
  description = "Stored in tofu state (encrypted state bucket); pass via TF_VAR_google_client_secret."
  type        = string
  default     = ""
  sensitive   = true
}

variable "allowed_emails" {
  description = "Closed list of emails that may sign in (set via TF_VAR_allowed_emails, not committed). Empty rejects everyone."
  type        = list(string)
  default     = []
}

locals {
  google_enabled = var.google_client_id != ""
}

resource "aws_cognito_identity_provider" "google" {
  count         = local.google_enabled ? 1 : 0
  user_pool_id  = aws_cognito_user_pool.main.id
  provider_name = "Google"
  provider_type = "Google"
  provider_details = {
    client_id        = var.google_client_id
    client_secret    = var.google_client_secret
    authorize_scopes = "openid email profile"
  }
  attribute_mapping = {
    email          = "email"
    email_verified = "email_verified"
    name           = "name"
    username       = "sub"
  }
}

resource "aws_cloudwatch_log_group" "presignup" {
  name              = "/aws/lambda/${var.name}-presignup"
  retention_in_days = 1
}

data "aws_iam_policy_document" "presignup_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "presignup" {
  name               = "${var.name}-presignup"
  assume_role_policy = data.aws_iam_policy_document.presignup_trust.json
}

resource "aws_iam_role_policy" "presignup_logs" {
  role = aws_iam_role.presignup.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.presignup.arn}:*"
    }]
  })
}

resource "aws_lambda_function" "presignup" {
  function_name    = "${var.name}-presignup"
  role             = aws_iam_role.presignup.arn
  runtime          = "python3.13"
  handler          = "presignup.handler"
  filename         = "${path.module}/lambda/presignup.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda/presignup.zip")
  timeout          = 3
  memory_size      = 128
  environment {
    variables = { ALLOWED_EMAILS = join(",", var.allowed_emails) }
  }
  depends_on = [aws_cloudwatch_log_group.presignup, aws_iam_role_policy.presignup_logs]
}

resource "aws_lambda_permission" "cognito_presignup" {
  statement_id  = "AllowCognitoPreSignUp"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.presignup.function_name
  principal     = "cognito-idp.amazonaws.com"
  source_arn    = aws_cognito_user_pool.main.arn
}
