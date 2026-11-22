# No secrets: identifiers and public configuration only.
output "kms_key_arn" { value = aws_kms_key.env.arn }
output "kms_alias" { value = aws_kms_alias.env.name }
output "checkpoints_bucket" { value = aws_s3_bucket.checkpoints.id }
output "artifacts_bucket" { value = aws_s3_bucket.artifacts.id }
output "ecr_repository_urls" { value = { for k, r in aws_ecr_repository.this : k => r.repository_url } }

output "vpc_id" { value = aws_vpc.main.id }
output "public_subnet_ids" { value = aws_subnet.public[*].id }
output "private_subnet_ids" { value = aws_subnet.private[*].id }
output "session_tasks_security_group_id" { value = aws_security_group.session_tasks.id }

output "aurora_endpoint" { value = aws_rds_cluster.main.endpoint }

output "cognito_issuer_url" { value = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.main.id}" }
output "cognito_hosted_domain" { value = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${var.region}.amazoncognito.com" }
output "cognito_client_ids" { value = { for k, c in aws_cognito_user_pool_client.this : k => c.id } }

output "github_apply_role_arn" { value = aws_iam_role.github_apply.arn }

output "web_url" { value = "https://${aws_cloudfront_distribution.web.domain_name}" }
output "web_bucket" { value = aws_s3_bucket.web.id }
output "web_distribution_id" { value = aws_cloudfront_distribution.web.id }
output "google_redirect_uri" { value = "${aws_cognito_user_pool_domain.main.domain}.auth.${var.region}.amazoncognito.com/oauth2/idpresponse" }
