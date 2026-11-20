# Progress: P1 AWS dev environment (append-only)

- 2026-11-19 · planning only: proposal, spec, design and tasks written by a worker; no code. Owner gates: cost brief approval before any apply (task 1.2); task 4.3 touches a protected workflow file and needs a lead PR.

## 2026-11-19 19:36 worker
- Task: 1.1, 1.3 - done (1.2 open: P1-1 not yet in decisions.md; tofu not installed on VM so tasks 2-5 validation needs it)
- Verified: bash scripts/aws-cost-check.sh -> OK ; bash scripts/tree-check.sh -> OK
- Notes for next session: prices are from knowledge, not fetched (aws.amazon.com blocked); owner/lead must verify before P1-1. Task 1.2 stays unticked until approval. Install OpenTofu (and check it is reachable) before tasks 2.1+.

## 2026-11-19 worker
- Task: 2.1, 2.2, 2.3 - done
- Verified: `just aws-validate` -> pass (tofu 1.8.5 fmt+validate x3, 4 policy tests); `just ci` -> exit 0; Sonnet evaluator PASS (planted dir fails tree-check)
- Notes for next session: OpenTofu is not preinstalled; install from the GitHub release zip (v1.8.5, github.com reachable) before `just aws-validate`. Policy is a stdlib Python plan-JSON checker (infra/tofu/policy), not conftest (design decision 7 left the engine open); classic aws_elb not banned. 1.2 gate still open; 3.x next.

## 2026-11-19 22:40 lead
- Task: rescue #479 (unblocks 3.x-5.x) - done
- Verified: `just aws-validate` -> 3x valid + 4 policy tests OK; a temp `aws_kms_key` with `not_an_arg` fails validate (provider schema loaded); `just ci` -> exit 0; Opus evaluator PASS
- Cause: `tofu init` fetches hashicorp/aws from registry.opentofu.org, which the VM proxy blocks (000); releases.hashicorp.com and GitHub release zips are reachable.
- Fix: `scripts/tofu-setup.sh` installs tofu 1.10.7 (SHA256SUMS) and mirrors hashicorp/aws 6.73.0 (HashiCorp-signed SHA256SUMS, pinned fingerprint) into a filesystem mirror; `just aws-validate` sets TF_CLI_CONFIG_FILE. Modules pin `aws ~> 6.73`. Design decision 9.
- Notes for next session: no owner network change needed. To bump the provider, set AWS_PROVIDER_VERSION in the script and the module constraint together. `.terraform.lock.hcl` is gitignored (mirror lock has one platform's hash only). Task 1.2 (owner cost approval P1-1) is still a gate; offline tasks 3-5 may proceed.

## 2026-11-19 worker
- Task: 3.1, 3.2, 3.3, 3.4 - done (attempt 2, Sonnet -> Opus; attempt 1 failed: RDS managed secret = Secrets Manager, no moto smoke)
- Verified: `just aws-validate` -> 3x valid + 5 policy tests; `just aws-moto-smoke` -> moto-smoke: OK (11 resources; Object Lock GOVERNANCE 1d, alias, SSE-KMS); `just ci` -> exit 0; Opus evaluator PASS
- Notes for next session: Aurora master password is a public placeholder replaced once at create by a local-exec (needs `aws` CLI on the applier; moves to `master_password_wo` when tofu >= 1.11); `check_plan.py` rejects manage_master_user_password. Imported clusters would keep the placeholder (README note worth adding). Task 4.3 workflow must provide the aws CLI. 1.2 gate still open. Next: 4.1, 4.2, 5.x.

## 2026-11-19 worker
- Task: 4.1, 4.2 - done (4.3 needs a lead PR, 4.4 waits on actionlint of 4.3)
- Verified: `just aws-validate` -> 3x valid + 5 + 8 policy tests OK; `just aws-moto-smoke` OK; `just ci` -> exit 0 (before final small fix: IAM read actions + test + design note, re-validated); Sonnet evaluator FAIL then PASS after fixes
- Notes for next session: OIDC trust sub is environment-based (`environment:aws-base-apply`), recorded in design.md; 4.3 workflow must use that environment and provide the aws CLI. No offline SCP test for guardrails (minor). 1.2 gate still open. Next: 5.1-5.4.

## 2026-11-20 worker
- Task: 5.1, 5.2, 5.3, 5.4 - done
- Verified: `just aws-validate` -> 3x valid; `just ci` -> exit 0 (run before the last shellcheck-only edit); `shellcheck scripts/aws-session.sh` clean; each `just aws-*` exits 3 with a clear message when no aws CLI/credentials. No Opus/Sonnet independent evaluator was run this session (self-checked only); online `aws-up`/`aws-smoke` untested (gate 1.2 open).
- Notes for next session: session stack takes base outputs via `target/aws/session.auto.tfvars.json` (written by the script from `tofu output -json` of base). Smoke check "Cognito token accepted by control plane" is a discovery-document check until T1 sign-in exists. Control plane DB URL comes from an optional SSM SecureString ARN; the env name `LOCKSMITH_DB_HOST`/`LOCKSMITH_OIDC_ISSUER` are informational, not yet read by the service. Remaining: 4.3/4.4 (lead PR, protected workflow), 6.1, 6.2, 7.1, gate 1.2.

## 2026-11-20 worker
- Task: 6.1, 6.2 - done
- Verified: `bash scripts/tree-check.sh` OK; `just ci` -> exit 0. No independent evaluator run (config + docs only); self-checked.
- Notes for next session: `.mcp.json` gets `aws` (awslabs.aws-api-mcp-server==1.6.1 via uvx, READ_OPERATIONS_ONLY, profile `locksmith-readonly`, us-east-1); package name/flags taken from PyPI, not verified against AWS docs (design decision 8 said verify): owner/lead should confirm. Remaining: 1.2 (owner gate), 4.3/4.4 (lead PR, protected workflow), 7.1 (`just apps-build`).

## 2026-11-20 worker (event)
- Task: 7.1 - done
- Verified: `just apps-build` exit 0 (desktop debug build ok); `just ci` exit 0 (aws-validate included earlier); no online aws-up/aws-smoke (gate 1.2 open).
- Notes for next session: remaining 1.2 (owner gate) and 4.3/4.4 (lead PR, protected workflow).

## 2026-11-20 lead
- Task: rescue #486 (Decision: 1.2 owner gate, 4.3/4.4 protected workflow) - handed to owner as #487
- Verified: all 10 unit prices in `docs/design/aws-dev-cost.csv` match the AWS Price List bulk API (us-east-1, fetched today; usage types listed in the brief); `bash scripts/aws-cost-check.sh` -> OK ($1.52 idle, $3.12/month). Workflow YAML parses; `actionlint` not run (no sanctioned install in the VM).
- Cause: approving spend and writing `.github/workflows/*` are owner-only (owner.md 2026-11-18, common.md trust root); neither a worker nor the lead can finish 1.2/4.3.
- Fix: brief's price caveat replaced with the verification evidence; owner issue #487 carries the cost decision, an Artifact brief and the full `aws-base-apply.yml` for the owner to commit.
- Notes for next session: on `approved` in #487 the lead records P1-1 in decisions.md and ticks 1.2. Once the workflow is on main, run `actionlint` on it and tick 4.3/4.4. Serverless v2 support for PG18 is not stated in AWS docs; the recorded fallback stays.
