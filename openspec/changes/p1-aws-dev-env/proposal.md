# Proposal: P1 AWS dev environment

## Why
Everything so far runs in `just up`. Some behaviour exists only in AWS (KMS wrapping, S3 Object Lock checkpoints, Cognito, Aurora auto-pause, Fargate), and a person cannot use the product in the cloud yet. A0-14 says a dev cloud comes only for what cannot be tested locally, and A0-16 to A0-18 fix its cost, guardrails and the rules for how Claude touches it. P1 builds exactly that and nothing more.

## What Changes
- **OpenTofu `base` stack** in `infra/tofu/base` (always on, about $1 to $2 a month idle): IAM roles, a customer-managed KMS key, S3 buckets (audit checkpoints with Object Lock governance mode, artifacts), ECR repositories, Aurora Serverless v2 PostgreSQL 18 with auto-pause (min 0 ACU), and a Cognito user pool (Essentials) with the app clients T1 expects.
- **OpenTofu `session` stack** in `infra/tofu/session` (on demand): ARM Fargate 0.25 vCPU tasks for the control plane and gateway with public IPs, no load balancer and no NAT, destroyed by `just aws-down` and by an auto-destroy timer.
- **Guardrails** as code: a $5 monthly AWS Budget (email at $1 and $3, deny-create action at $5), standing SCPs (one region, banned services, no large instances, no Marketplace or reservations, no guardrail changes) and Cost Anomaly Detection.
- **GitHub Actions OIDC apply:** a manually dispatched workflow assumes a scoped role through OIDC (no long-lived keys) to plan and apply `base`; `session` is applied only through `just aws-up`. Plan output is posted to the run summary with secrets redacted.
- **Claude inspection:** the AWS MCP Server is configured read-only in `.mcp.json`; a runbook and a change-brief template implement A0-18 (every mutating call needs owner approval, tag `created-by=claude-mcp`, import or destroy before the session ends).
- **AWS-only smoke checks** named in A0-14: KMS wrap and unwrap, S3 Object Lock write, Aurora resume from pause, Cognito token against the control plane JWKS, Fargate task starts and answers `/health`.

## Out of scope
- Production accounts, multi-AZ or multi-region, Control Tower, the prod RDS or Aurora decision (A0-8).
- Any custom domain, ALB, NAT gateway, VPC interface endpoints, Secrets Manager or Route 53 zones (banned in dev by A0-16).
- Application code changes. The control plane and gateway run unchanged from ECR images.
- Creating the AWS account, Organization and Identity Center: those are owner-only admin steps (see Owner gates).

## Owner gates
Per owner decision 2026-11-18, any AWS decision that affects budget needs owner approval, with the monthly cost of each option. Tasks 1.1 and 2.0 are gates: no `tofu apply` and no AWS spend until the lead records owner approval of the cost brief in `openspec/decisions.md`. Planning, `tofu validate` and local policy tests need no approval.

## Depends on
None. T1 only needs the Cognito issuer URL and client ids as configuration, which task group 3 emits as outputs.

## Usable outcome
The owner can run `just aws-up` and reach a working control plane and gateway in AWS, sign in through Cognito, and run `just aws-down` to return to about $1 to $2 a month, with the budget and SCPs stopping any overrun.
