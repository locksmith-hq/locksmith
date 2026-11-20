# Session stack: Fargate ARM tasks that exist only while a session runs (A0-13, A0-16).
# No ALB, no NAT, no interface endpoints: tasks get a public IP and are reached
# directly from `allowed_cidr`. Apply with `just aws-up`, remove with `just aws-down`.
terraform {
  required_version = ">= 1.8.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      project = "locksmith"
      env     = "dev"
      stack   = "session"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  services = {
    control-plane = { port = 8080, image = "locksmith-control-plane" }
    gateway       = { port = 8081, image = "locksmith-gateway" }
  }
  expires_at = timeadd(var.start_time, "${var.session_hours}h")
}

resource "aws_ecs_cluster" "session" {
  name = "${var.name}-session"
}

resource "aws_cloudwatch_log_group" "svc" {
  for_each          = local.services
  name              = "/locksmith/${var.name}/${each.key}"
  retention_in_days = 1
}

# Execution role: pull from ECR, write logs, read the optional SSM parameter.
data "aws_iam_policy_document" "ecs_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-session-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_trust.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution_extra" {
  count = var.database_url_parameter_arn == "" ? 0 : 1
  statement {
    actions   = ["ssm:GetParameters"]
    resources = [var.database_url_parameter_arn]
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "execution_extra" {
  count  = var.database_url_parameter_arn == "" ? 0 : 1
  name   = "ssm-database-url"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_extra[0].json
}

# Task role: only the environment KMS key (wrap/unwrap) and the S3 buckets are reachable.
resource "aws_iam_role" "task" {
  name               = "${var.name}-session-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_trust.json
}

data "aws_iam_policy_document" "task" {
  statement {
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "kms-env-key"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

resource "aws_ecs_task_definition" "svc" {
  for_each                 = local.services
  family                   = "${var.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name         = each.key
    image        = "${var.ecr_repository_urls[each.value.image]}:${var.image_tag}"
    essential    = true
    portMappings = [{ containerPort = each.value.port, protocol = "tcp" }]
    # Non-secret configuration only. LOCKSMITH_DEV_AUTH is deliberately absent.
    environment = concat(
      each.key == "control-plane" ? [
        { name = "LOCKSMITH_BIND", value = "0.0.0.0:${each.value.port}" },
        { name = "LOCKSMITH_DB_HOST", value = var.aurora_endpoint },
        { name = "LOCKSMITH_OIDC_ISSUER", value = var.cognito_issuer_url },
        ] : [
        { name = "LOCKSMITH_GATEWAY_BIND", value = "0.0.0.0:${each.value.port}" },
      ],
    )
    secrets = each.key == "control-plane" && var.database_url_parameter_arn != "" ? [
      { name = "DATABASE_URL", valueFrom = var.database_url_parameter_arn },
    ] : []
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.svc[each.key].name
        awslogs-region        = var.region
        awslogs-stream-prefix = each.key
      }
    }
  }])
}

resource "aws_vpc_security_group_ingress_rule" "svc" {
  for_each          = local.services
  security_group_id = var.session_tasks_security_group_id
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  cidr_ipv4         = var.allowed_cidr
  description       = "${each.key} from the session owner"
}

resource "aws_ecs_service" "svc" {
  for_each        = local.services
  name            = each.key
  cluster         = aws_ecs_cluster.session.id
  task_definition = aws_ecs_task_definition.svc[each.key].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.public_subnet_ids
    security_groups  = [var.session_tasks_security_group_id]
    assign_public_ip = true
  }

  # The timer scales services to zero; do not fight it on the next plan.
  lifecycle {
    ignore_changes = [desired_count]
  }
}

# Auto-destroy timer: one-time EventBridge Scheduler entry that sets desired count 0
# on both services after `session_hours`, so a forgotten session costs nothing more.
data "aws_iam_policy_document" "scheduler_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "timer" {
  name               = "${var.name}-session-timer"
  assume_role_policy = data.aws_iam_policy_document.scheduler_trust.json
}

data "aws_iam_policy_document" "timer" {
  statement {
    actions   = ["ecs:UpdateService"]
    resources = [for s in aws_ecs_service.svc : s.id]
  }
}

resource "aws_iam_role_policy" "timer" {
  name   = "scale-to-zero"
  role   = aws_iam_role.timer.id
  policy = data.aws_iam_policy_document.timer.json
}

resource "aws_scheduler_schedule" "stop" {
  for_each                     = local.services
  name                         = "${var.name}-stop-${each.key}"
  schedule_expression          = "at(${trimsuffix(local.expires_at, "Z")})"
  schedule_expression_timezone = "UTC"
  action_after_completion      = "DELETE"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = "arn:aws:scheduler:::aws-sdk:ecs:updateService"
    role_arn = aws_iam_role.timer.arn
    input = jsonencode({
      Cluster      = aws_ecs_cluster.session.arn
      Service      = aws_ecs_service.svc[each.key].name
      DesiredCount = 0
    })
  }
}

output "cluster_name" { value = aws_ecs_cluster.session.name }
output "service_names" { value = [for s in aws_ecs_service.svc : s.name] }
output "expires_at" { value = local.expires_at }
