# Decided foundations

Every proposal and design must follow these. To change one, raise a `needs-owner` decision; never contradict a line silently.

**Agents may only append.** Each new line links the `needs-owner` issue where the owner approved it. Never edit or delete existing lines; a reversal is a new line that names the one it replaces. `scripts/check-task-edits.sh` enforces this.

## A0 data and cloud foundations (approved in #37, 2026-11-17; details and evidence in `openspec/changes/a0-data-and-cloud-foundations/design.md`)
- A0-1 · PostgreSQL 18 everywhere: `postgres:18` locally, RDS or Aurora in AWS, and for self-hosters.
- A0-2 · Vanilla Postgres only; `pgcrypto` only if a spike needs it. No pgmq: jobs use a `FOR UPDATE SKIP LOCKED` table (later `apalis`).
- A0-3 · Aurora DSQL is rejected.
- A0-4 · Multi-tenancy: shared tables, `org_id` on every tenant row, `FORCE ROW LEVEL SECURITY`. The app role is neither table owner nor `BYPASSRLS`; migrations run as a separate owner role. Enterprise may get a dedicated database with the same schema.
- A0-5 · Tenant context is set per transaction with `set_config('app.org_id', $1, true)` in the same sqlx transaction. Session-level `SET` is banned and checked by a lint or test.
- A0-6 · Primary keys are UUIDv7 (`uuidv7()` or app-generated v7). No serial IDs are exposed.
- A0-7 · Every encrypted value carries a versioned header `magic(2) ‖ format_ver(1) ‖ alg_id(1) ‖ key_id(16) ‖ nonce ‖ ciphertext ‖ tag`, with AAD = `org_id ‖ secret_id ‖ version ‖ purpose`. The DEK wrap uses the same header.
- A0-8 · No RDS Proxy at first; each service has its own sqlx pool. Dev uses Aurora Serverless v2 with auto-pause (min 0 ACU). The prod choice between RDS and Aurora Multi-AZ is made in P1 from load numbers.
- A0-9 · Every org row has a `region` from day one. One US region (us-east-1) first, an EU cell later. Regions are separate deployments with no cross-region database. EU data residency is not needed at launch.
- A0-10 · KMS: one customer-managed key per environment per region wraps the gateway keys; a customer-supplied key is an enterprise option. Gateways cache unwrapped DEKs briefly to stay within KMS rate limits.
- A0-11 · Audit hash chain lives in Postgres; signed checkpoints go to S3 Object Lock (compliance mode in prod, governance mode in dev).
- A0-12 · AWS Organizations plus IAM Identity Center. OUs: Security (Log Archive, Audit), Infrastructure, Workloads (`control-plane-{dev,prod}`, `gateway-{dev,prod}`), Sandbox. Control Tower is optional later.
- A0-13 · Compute: ECS Fargate first, Helm kept for self-host. In dev, Fargate tasks (ARM, 0.25 vCPU) exist only during a test session.
- A0-14 · Local parity: every AWS service has a local stand-in that speaks the same protocol, behind a trait or standard interface (Postgres 18, OpenBao transit for KMS, moto for S3/STS/Cognito APIs, Keycloak for the OIDC browser flow). Only AWS-only behaviour is tested in dev, each with a named P1 smoke check.
- A0-15 · Users: Cognito user pools (Essentials) in our cloud, Keycloak locally, any OIDC issuer for self-hosters. Services speak generic OIDC only (JWKS-verified JWTs); no Cognito SDK calls on the request path.
- A0-16 · Dev costs under $5/month (about $1–2 idle): an always-on `base` OpenTofu stack and an on-demand `session` stack (`just aws-up` / `just aws-down`, auto-destroyed). Banned in dev: ALB, NAT gateway, VPC interface endpoints, Secrets Manager, Route 53 zones, log retention over 1 day.
- A0-17 · Budget guardrails: a $5/month AWS Budget on the dev account (email at $1 and $3; a deny-create SCP at $5), standing SCPs (one region, no banned items, no large instances, Marketplace, reservations or guardrail changes), and Cost Anomaly Detection.
- A0-18 · No AWS keys in a Claude session. Reads through the AWS MCP server run freely; every mutating call needs owner approval after a change brief (what, cost, blast radius, security, rollback), is tagged `created-by=claude-mcp`, and is imported into OpenTofu or destroyed before the session ends. MCP can never change IAM, Organizations, SCPs, Budgets or Identity Center.
