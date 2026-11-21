# Cognito Essentials user pool with a hosted domain prefix (no custom domain, no Route 53).
resource "aws_cognito_user_pool" "main" {
  name           = var.name
  user_pool_tier = "ESSENTIALS"

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]
  mfa_configuration        = "OFF"

  admin_create_user_config {
    allow_admin_create_user_only = true
  }
  password_policy {
    minimum_length    = 14
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }
}

resource "aws_cognito_user_pool_domain" "main" {
  domain       = var.cognito_domain_prefix
  user_pool_id = aws_cognito_user_pool.main.id
}

locals {
  cognito_clients = {
    "locksmith-web"     = { callbacks = var.web_callback_urls, logouts = var.web_logout_urls }
    "locksmith-desktop" = { callbacks = var.desktop_callback_urls, logouts = var.desktop_logout_urls }
    "smith-cli"         = { callbacks = var.cli_callback_urls, logouts = [] }
  }
}

# Public clients (PKCE, authorization-code flow only): no client secrets exist.
resource "aws_cognito_user_pool_client" "this" {
  for_each     = local.cognito_clients
  name         = each.key
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret                      = false
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = each.value.callbacks
  logout_urls                          = length(each.value.logouts) > 0 ? each.value.logouts : null
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
}
