# Design: P1 AWS dev environment

## Context
- Binding decisions: A0-1 (PostgreSQL 18), A0-8 (Aurora Serverless v2 auto-pause in dev), A0-9 (us-east-1), A0-10 (one KMS key per environment), A0-11 (S3 Object Lock, governance mode in dev), A0-12 (Organizations, Identity Center), A0-13 (Fargate ARM 0.25 vCPU only during a session), A0-14 to A0-18.
- `infra/` holds only compose today; `infra/README.md` requires OpenTofu with no secrets committed. `scripts/tree-check.sh` must learn `infra/tofu`.
- No AWS account is reachable from the agent VM, so all code is validated offline (`tofu validate`, policy tests) and applied only by the owner or the CI apply workflow after approval.

## Goals / Non-Goals
**Goals:** reproducible dev cloud under $5 a month; keyless CI apply; read-only Claude inspection; named smoke checks.
**Non-Goals:** production, domains, load balancing, application changes.

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **OpenTofu with the AWS provider, two root modules** (`base`, `session`) sharing remote state in an S3 bucket with lockfile locking. | One stack (an idle apply would risk the always-on data); Terraform (BSL); CDK/Pulumi (another runtime). | A0-16; OpenTofu is MPL-2.0 under the Linux Foundation. **[verify version and release date at apply]** |
| 2 | **Fargate tasks in public subnets with public IPs, no NAT, no ALB**; reached by task IP printed by `just aws-up`. | NAT gateway (about $32 a month), ALB (about $16 a month), VPC endpoints (banned). | A0-16; AWS pricing pages, to be cited with figures in task 1.1. |
| 3 | **Aurora Serverless v2 PostgreSQL 18 with min 0 ACU auto-pause.** If the engine version is not yet offered, fall back to the newest supported major and record it. | RDS `db.t4g.micro` (always on); DSQL (A0-3 rejects). | A0-1, A0-8; AWS docs on Serverless v2 scale-to-zero. **[verify PG18 availability and pause latency at apply]** |
| 4 | **Cognito Essentials user pool with an authorization-code app client and a hosted domain prefix.** Outputs issuer URL and client ids as configuration for T1. | A Lambda GitHub shim now (decision belongs to T1 design decision 3 and a later change). | A0-15; Cognito pricing: free tier of monthly active users. **[verify]** |
| 5 | **GitHub OIDC provider and a role trusted only for this repository and the dispatched workflow ref.** | Stored IAM user keys (violates A0-18 spirit); self-hosted runner. | GitHub docs, "Configuring OpenID Connect in AWS". |
| 6 | **Guardrails split by who may change them:** Budget and SCPs live in a separate `guardrails` root applied only by the owner from the management account. The CI role cannot touch them. | Putting them in `base` (CI could weaken its own limits). | A0-17, A0-18. |
| 7 | **Policy check with `tofu validate` plus a small rule file run by an OSS policy engine** that rejects banned resource types in the plan JSON. | Hand-rolled grep (fragile). | A0-16 ban list. The engine is chosen at apply by comparing `conftest` (Apache-2.0) and `tflint` rules and recording the result. |
| 8 | **AWS MCP server read-only** via a read-only IAM role assumed from the owner's machine, not from the cloud VM. Mutations go through the brief template and owner approval. | Giving Claude keys (A0-18 forbids). | A0-18. **[verify the current official AWS MCP server name and auth at apply]** |
| 9 | **Offline provider install (lead rescue #479):** `scripts/tofu-setup.sh` installs pinned OpenTofu 1.10.7 from its GitHub release (SHA256SUMS checked) and puts `hashicorp/aws` 6.73.0 from releases.hashicorp.com (SHA256SUMS signed by HashiCorp key `C874 011F 0AB4 0511 0D02 1055 3436 5D94 72D7 468F`, verified) into a filesystem mirror; `just aws-validate` uses it via `TF_CLI_CONFIG_FILE`. Lock files stay uncommitted until `tofu providers lock` can reach the registry for all platforms. | Allowing registry.opentofu.org in the VM (owner setting, not needed); vendoring the 200 MB provider in git. | VM probe 2026-11-19: registry.opentofu.org 000, releases.hashicorp.com 200, GitHub release zips 302→200. The provider binary is MPL-2.0 and identical across registries. |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| OpenTofu | MPL-2.0 | verify at apply | verify | IaC engine | tool only, not linked |
| terraform-provider-aws | MPL-2.0 | verify at apply | verify | AWS resources | tool only |
| conftest or tflint | Apache-2.0 / MPL-2.0 | verify at apply | verify | plan policy | tool only |
| moto | Apache-2.0 | already in local stack | n/a | offline unit checks | tool only |

Built in-house: only the HCL, the `just aws-*` recipes and the smoke scripts. Searched first: community Terraform modules for Aurora, Cognito and OIDC roles; prefer the official `terraform-aws-modules` (Apache-2.0) where it keeps the resource count and cost low, otherwise plain resources.

## Cost estimate (to be verified with pricing pages in task 1.1, owner approves before apply)
| Item | Idle per month | Session |
|---|---|---|
| KMS key | $1.00 plus requests | same |
| Aurora Serverless v2 at 0 ACU | storage only, about $0.10 per GB | ACU-hours while awake |
| S3, ECR, Cognito (free tier), Budgets | under $0.50 | same |
| Fargate ARM 0.25 vCPU, 0.5 GB, two tasks | $0 | about $0.02 per hour |
| Public IPv4 per task | $0 | about $0.005 per hour each |

## Risks and mitigations
- **Cost drift:** forgotten session. Mitigation: auto-destroy timer, budget SCP, `just aws-status` in the worker preflight when credentials exist.
- **Drift from Claude changes:** `just aws-drift` plus the tag rule.
- **Aurora PG18 or scale-to-zero not available in us-east-1:** recorded fallback, flagged to the lead.

## Open Questions
- Does the owner want the AWS account and Organization created now or only when T1 and T3 need a hosted sign-in? (Owner gate; lead asks.)

## How an agent debugs this
- Offline: `just aws-validate` (tofu fmt and validate, policy tests), `tofu plan` JSON in `target/aws/`.
- Online (owner machine only): AWS MCP server read-only (CloudWatch logs, describe calls), `just aws-status`, `just aws-smoke`, `just aws-drift`.
- Logs: CloudWatch groups with one-day retention; the control plane's OpenTelemetry traces go to the same collector as locally.
- DB: connect through the session task or a temporary `psql` task; never open the cluster publicly.

## Deviation recorded (worker, 2026-11-19): OIDC trust subject
Decision 5 says "dispatched workflow ref". The apply role trusts `sub = repo:locksmith-hq/locksmith:environment:aws-base-apply` (exact, `StringEquals`, aud `sts.amazonaws.com`), because a job in an approval environment gets an environment-based `sub`. Branch limits therefore live in the GitHub environment (required reviewers, deployment branch main), which is owner-configured and not in git. Task 4.3's workflow must declare `environment: aws-base-apply` and provide the `aws` CLI.
