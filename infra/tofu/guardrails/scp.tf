# Standing SCPs and the budget-triggered deny-create SCP. Requires the
# SERVICE_CONTROL_POLICY policy type to be enabled on the organization root.
locals {
  # Only inexpensive instance sizes; everything bigger is denied.
  allowed_ec2_types = ["*.nano", "*.micro", "*.small", "*.medium"]
  allowed_rds_class = ["db.serverless", "db.t4g.micro", "db.t4g.small", "db.t3.micro", "db.t3.small"]
  # Global services have no regional endpoint in us-east-1 terms; exempt them from the region lock.
  region_exempt_actions = [
    "iam:*", "organizations:*", "sts:*", "budgets:*", "ce:*", "cur:*", "account:*",
    "route53:*", "route53domains:*", "cloudfront:*", "waf:*", "support:*", "trustedadvisor:*",
    "health:*", "sso:*", "sso-directory:*", "identitystore:*", "billing:*", "payments:*",
    "tax:*", "pricing:*", "aws-portal:*", "globalaccelerator:*", "s3:GetBucketLocation",
    "s3:ListAllMyBuckets",
  ]
}

resource "aws_organizations_policy" "region_lock" {
  name        = "${var.name}-region-lock"
  description = "Limit the account to ${var.region}."
  type        = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyOutsideRegion"
      Effect    = "Deny"
      NotAction = local.region_exempt_actions
      Resource  = "*"
      Condition = { StringNotEquals = { "aws:RequestedRegion" = [var.region] } }
    }]
  })
}

resource "aws_organizations_policy" "deny_banned" {
  name        = "${var.name}-deny-banned"
  description = "Deny resource types that alone break the $5 budget, large instances, Marketplace, reservations and guardrail changes."
  type        = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyLoadBalancers"
        Effect   = "Deny"
        Action   = ["elasticloadbalancing:CreateLoadBalancer", "elasticloadbalancing:CreateTargetGroup"]
        Resource = "*"
      },
      {
        Sid      = "DenyNatGateways"
        Effect   = "Deny"
        Action   = ["ec2:CreateNatGateway"]
        Resource = "*"
      },
      {
        Sid      = "DenyNonGatewayVpcEndpoints"
        Effect   = "Deny"
        Action   = ["ec2:CreateVpcEndpoint"]
        Resource = "*"
        Condition = {
          StringNotLike = { "ec2:VpceServiceName" = ["com.amazonaws.*.s3", "com.amazonaws.*.dynamodb"] }
        }
      },
      {
        Sid      = "DenySecretsManager"
        Effect   = "Deny"
        Action   = ["secretsmanager:CreateSecret", "secretsmanager:ReplicateSecretToRegions"]
        Resource = "*"
      },
      {
        Sid      = "DenyRoute53Zones"
        Effect   = "Deny"
        Action   = ["route53:CreateHostedZone", "route53domains:RegisterDomain"]
        Resource = "*"
      },
      {
        Sid       = "DenyLargeEc2Instances"
        Effect    = "Deny"
        Action    = ["ec2:RunInstances"]
        Resource  = "arn:${data.aws_partition.current.partition}:ec2:*:*:instance/*"
        Condition = { StringNotLike = { "ec2:InstanceType" = local.allowed_ec2_types } }
      },
      {
        Sid       = "DenyLargeRdsInstances"
        Effect    = "Deny"
        Action    = ["rds:CreateDBInstance", "rds:ModifyDBInstance"]
        Resource  = "*"
        Condition = { StringNotLike = { "rds:DatabaseClass" = local.allowed_rds_class } }
      },
      {
        Sid    = "DenyMarketplaceAndReservations"
        Effect = "Deny"
        Action = [
          "aws-marketplace:Subscribe", "aws-marketplace:AcceptAgreementRequest",
          "ec2:PurchaseReservedInstancesOffering", "ec2:PurchaseHostReservation", "ec2:PurchaseCapacityBlock",
          "rds:PurchaseReservedDBInstancesOffering", "elasticache:PurchaseReservedCacheNodesOffering",
          "savingsplans:CreateSavingsPlan",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyGuardrailChanges"
        Effect = "Deny"
        Action = [
          "organizations:*", "budgets:*", "ce:*", "account:*",
          "sso:*", "sso-directory:*", "identitystore:*",
        ]
        Resource = "*"
      },
    ]
  })
}

# Attached automatically by the budget action when spend reaches the limit.
resource "aws_organizations_policy" "deny_create" {
  name        = "${var.name}-deny-create"
  description = "Budget exceeded: block creating new billable resources."
  type        = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyCreateBillable"
      Effect = "Deny"
      Action = [
        "ec2:RunInstances", "ec2:CreateVolume", "ec2:AllocateAddress", "ec2:CreateSnapshot",
        "ecs:CreateService", "ecs:RunTask", "ecs:CreateCluster",
        "rds:CreateDBCluster", "rds:CreateDBInstance", "rds:RestoreDBClusterFromSnapshot",
        "kms:CreateKey", "ecr:CreateRepository", "s3:CreateBucket",
        "cognito-idp:CreateUserPool", "logs:CreateLogGroup",
        "lambda:CreateFunction", "dynamodb:CreateTable", "sqs:CreateQueue", "sns:CreateTopic",
        "elasticache:Create*", "redshift:Create*", "es:CreateDomain", "kafka:CreateCluster*",
      ]
      Resource = "*"
    }]
  })
}

resource "aws_organizations_policy_attachment" "region_lock" {
  policy_id = aws_organizations_policy.region_lock.id
  target_id = var.scp_target_id
}

resource "aws_organizations_policy_attachment" "deny_banned" {
  policy_id = aws_organizations_policy.deny_banned.id
  target_id = var.scp_target_id
}
