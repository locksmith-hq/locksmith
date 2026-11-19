resource "aws_budgets_budget" "monthly" {
  name         = "${var.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = var.alert_thresholds_usd
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "ABSOLUTE_VALUE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = var.alert_emails
    }
  }
}

# Role the Budgets service assumes to attach the deny-create SCP at the limit.
data "aws_iam_policy_document" "budget_action_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["budgets.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "budget_action_permissions" {
  statement {
    actions   = ["organizations:AttachPolicy", "organizations:DetachPolicy"]
    resources = [aws_organizations_policy.deny_create.arn, "arn:${data.aws_partition.current.partition}:organizations::*:*/o-*/*"]
  }
  statement {
    actions   = ["organizations:DescribePolicy", "organizations:ListPoliciesForTarget"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "budget_action" {
  name               = "${var.name}-budget-action"
  assume_role_policy = data.aws_iam_policy_document.budget_action_trust.json
}

resource "aws_iam_role_policy" "budget_action" {
  name   = "attach-deny-create-scp"
  role   = aws_iam_role.budget_action.id
  policy = data.aws_iam_policy_document.budget_action_permissions.json
}

# At 100% of the budget (actual spend) attach the deny-create SCP automatically.
resource "aws_budgets_budget_action" "deny_create" {
  budget_name        = aws_budgets_budget.monthly.name
  action_type        = "APPLY_SCP_POLICY"
  approval_model     = "AUTOMATIC"
  notification_type  = "ACTUAL"
  execution_role_arn = aws_iam_role.budget_action.arn

  action_threshold {
    action_threshold_type  = "PERCENTAGE"
    action_threshold_value = 100
  }

  definition {
    scp_action_definition {
      policy_id  = aws_organizations_policy.deny_create.id
      target_ids = [var.scp_target_id]
    }
  }

  subscriber {
    subscription_type = "EMAIL"
    address           = var.alert_emails[0]
  }
}
