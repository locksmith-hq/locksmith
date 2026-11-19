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
