# Tasks: P1 AWS dev environment

## 1. Cost brief and gate [sonnet]
- [x] 1.1 Write `docs/design/aws-dev-cost.md`: each resource with a cited price page, monthly idle and session cost, and options (Aurora PG18 vs fallback, Cognito hosted domain). Owner-facing, with an Artifact brief draft.
- [ ] 1.2 Gate: confirm `openspec/decisions.md` records owner approval of the cost brief (P1-1). Otherwise stop applying anything and report to the lead; offline tasks 2 to 4 may continue.
- [x] 1.3 Verify: the brief's totals reproduce from its own table (`bash scripts/aws-cost-check.sh` or a documented calculation).

## 2. Tooling and layout [sonnet]
- [x] 2.1 Teach `scripts/tree-check.sh` the `infra/tofu/{guardrails,base,session}` layout; add `just aws-validate` (`tofu fmt -check`, `tofu validate` with no backend).
- [x] 2.2 Plan policy: rule file rejecting ALB, NAT gateway, interface endpoints, Secrets Manager, Route 53 zones, log retention over 1 day, large instances; tests with sample plan JSON.
- [x] 2.3 Verify: `just aws-validate` and the policy test pass; a planted ALB fails.

## 3. Base stack [sonnet]
- [x] 3.1 `infra/tofu/base`: state backend bootstrap notes, KMS key and alias, S3 (checkpoints with Object Lock governance, artifacts), ECR repos, tags `project=locksmith, env=dev`.
- [x] 3.2 Aurora Serverless v2 (PG18 or recorded fallback, min 0 ACU auto-pause), private subnets, security group open only to the session tasks.
- [x] 3.3 Cognito Essentials pool, hosted domain prefix, `locksmith-web`, `locksmith-desktop`, `smith-cli` clients; outputs issuer URL and client ids (no secrets).
- [x] 3.4 Verify: `just aws-validate`; moto-backed smoke of the S3 and KMS modules where supported.

## 4. Guardrails and OIDC apply [sonnet]
- [x] 4.1 `infra/tofu/guardrails` (owner-applied): $5 Budget with $1/$3 email and deny-create action, SCPs, Cost Anomaly Detection.
- [x] 4.2 GitHub OIDC provider and apply role scoped to this repo and workflow; `infra/tofu/base` trust policy test.
- [ ] 4.3 Manual workflow `aws-base-apply.yml`: lint-class job only, `workflow_dispatch`, plan with approval environment, redacted summary. (Workflow files are protected: this task is a lead PR the owner merges.)
- [ ] 4.4 Verify: `just aws-validate`, `actionlint` on the workflow.

## 5. Session stack and smoke checks [sonnet]
- [x] 5.1 `infra/tofu/session`: ECS cluster, ARM Fargate task definitions for control plane and gateway from ECR images, public IP, task role, one-day log groups, auto-destroy timer.
- [x] 5.2 `just aws-up`, `aws-down`, `aws-status`, `aws-drift`; they refuse to run without credentials and never print them.
- [x] 5.3 `just aws-smoke` with the five named checks; output contains no secret or token.
- [x] 5.4 Verify: `just aws-validate`; scripts pass `shellcheck` and a dry run with no credentials exits with a clear message.

## 6. Claude inspection and runbook [sonnet]
- [x] 6.1 Add the read-only AWS MCP server to `.mcp.json` (if the file is protected, propose via the lead) and `docs/aws-runbook.md` with the change-brief template and the `created-by=claude-mcp` rule.
- [x] 6.2 Verify: `bash scripts/tree-check.sh` and `just ci`.

## 7. Local verification
- [ ] 7.1 `just aws-validate`, the policy tests, `just apps-build`, then `just ci`. Online `aws-up` and `aws-smoke` run only after the owner gate and are logged in progress.md.
