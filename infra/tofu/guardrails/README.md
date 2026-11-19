# guardrails stack

Owner-applied from the Organizations management account (never from CI; the CI role is denied Organizations, Budgets and Cost Explorer). Contains:
- a $5 monthly Budget with email alerts at $1 and $3 and an automatic budget action that attaches the deny-create SCP at 100%;
- standing SCPs: region lock (us-east-1), a deny list (ALB, NAT, non-gateway VPC endpoints, Secrets Manager, Route 53 zones, large EC2/RDS, Marketplace, reservations, changes to guardrails);
- Cost Anomaly Detection (per-service monitor, daily email).

Prerequisites: Organizations with the SERVICE_CONTROL_POLICY type enabled, Cost Explorer enabled. SCPs do not bind the management account, so attach to the dev member account or OU (`scp_target_id`).

Apply: `tofu init -backend=false` for validation only; for a real apply use a separate state key. Supply emails at apply time, never in git:
`tofu apply -var 'alert_emails=["you@example.com"]' -var 'scp_target_id=ou-xxxx-xxxxxxxx'`.
After the budget action fires, detach `*-deny-create` from the target once spend is understood.
