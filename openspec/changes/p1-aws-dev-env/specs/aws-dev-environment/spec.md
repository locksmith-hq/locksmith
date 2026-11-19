# Spec Delta

## Purpose
A low-cost, guard-railed AWS dev environment managed as code, applied from CI and inspected by Claude read-only.

## ADDED Requirements

### Requirement: Two stacks with an idle cost ceiling
The dev environment SHALL consist of an always-on `base` OpenTofu stack and an on-demand `session` stack. With no session running, the account SHALL cost no more than $5 a month, and the design SHALL estimate each resource.

#### Scenario: Idle
- **WHEN** `just aws-down` has completed
- **THEN** no Fargate task, public IPv4 address, load balancer or NAT gateway exists and the Aurora cluster is paused or at 0 ACU

#### Scenario: Banned resource
- **WHEN** a plan adds an ALB, NAT gateway, VPC interface endpoint, Secrets Manager secret, Route 53 zone or log retention over one day
- **THEN** the policy check fails before apply

### Requirement: Budget and SCP guardrails
The account SHALL have a $5 monthly Budget that emails at $1 and $3 and applies a deny-create SCP at $5, standing SCPs limiting it to one region and denying large instances, Marketplace, reservations and changes to the guardrails, and Cost Anomaly Detection.

#### Scenario: Budget exceeded
- **WHEN** forecast or actual spend reaches $5
- **THEN** the deny-create SCP is attached and creating new billable resources fails

### Requirement: Keyless apply from CI
Applying the `base` stack from GitHub Actions SHALL use OIDC federation to a role scoped to the repository and branch. No AWS access key SHALL be stored in the repository, Actions secrets or a Claude session.

#### Scenario: Apply
- **WHEN** the owner dispatches the apply workflow
- **THEN** the job assumes the role through OIDC and the plan output contains no secret values

### Requirement: Claude changes need approval and leave no drift
Claude SHALL read AWS through the read-only AWS MCP server. Every mutating call SHALL need owner approval after a change brief (what, cost, blast radius, security, rollback), SHALL be tagged `created-by=claude-mcp`, and SHALL be imported into OpenTofu or destroyed before the session ends. Claude SHALL NOT change IAM, Organizations, SCPs, Budgets or Identity Center.

#### Scenario: Untracked resource
- **WHEN** `just aws-drift` finds a resource tagged `created-by=claude-mcp` that OpenTofu does not manage
- **THEN** it reports it and fails

### Requirement: AWS-only behaviour has named smoke checks
Each behaviour that has no local stand-in SHALL have a named smoke check run by `just aws-smoke`: KMS wrap and unwrap, S3 Object Lock write, Aurora resume, Cognito token accepted by the control plane, and a Fargate task answering `/health`.

#### Scenario: Smoke run
- **WHEN** `just aws-up` finished and `just aws-smoke` runs
- **THEN** each check prints PASS and none logs a plaintext secret or token
