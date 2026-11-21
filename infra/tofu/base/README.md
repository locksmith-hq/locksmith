# base stack

Always-on dev resources: KMS key and alias, S3 (checkpoints with Object Lock governance, artifacts), ECR, a small VPC, Aurora Serverless v2 and a Cognito Essentials pool. Tags `project=locksmith, env=dev` come from the provider `default_tags`. Resources are added only through the policy in `../policy` (no NAT, ALB, interface endpoints, Secrets Manager secrets of our own, Route 53 zones).

## State backend bootstrap (owner, once)
1. Create an S3 bucket `locksmith-tfstate-<account-id>` in us-east-1 with versioning and default encryption, by hand or CLI (it must exist before this stack, so it is not in this stack).
2. `tofu init -backend-config="bucket=locksmith-tfstate-<account-id>" -backend-config="key=base/terraform.tfstate" -backend-config="region=us-east-1" -backend-config="use_lockfile=true"` after adding an empty `backend "s3" {}` block locally (not committed until the bucket exists).
3. `just aws-validate` always uses `-backend=false`.

## Moto smoke (opt-in)
`just aws-moto-smoke` (`tests/moto-smoke.sh`) applies `kms.tf`, `s3.tf` and `variables.tf` from a scratch copy to a local moto server (pinned `moto[server]`, pip-installed into `~/.cache/locksmith/moto-venv`, so it needs PyPI once) with fake credentials, then checks `alias/locksmith-dev` (enabled, rotation on), checkpoints Object Lock GOVERNANCE for 1 day with versioning, SSE-KMS and public access blocks on both buckets. It is not part of `just ci`. Network, Aurora and Cognito are covered by `just aws-validate` only.

## Notes
- Aurora: no usable password in code, state, plan or outputs, and no Secrets Manager secret (A0-16; the plan policy rejects `manage_master_user_password`). Write-only/ephemeral passwords (`master_password_wo`) need OpenTofu 1.11+ and the pinned 1.10.7 rejects them; the `random` provider is not in the offline mirror either. AWS still requires a master password at create, so the cluster is created with a public, non-secret bootstrap value, and a create-time `local-exec` provisioner replaces it at once with a random password that is never printed or kept (the applying machine needs the `aws` CLI). Apps and operators use IAM database auth. Break-glass: reset it with `aws rds modify-db-cluster --master-user-password` and discard it after use. Once tofu is 1.11+, switch to `master_password_wo` with an ephemeral random value and drop the provisioner.
- `aurora_engine_version` defaults to PG18 (`18.6`; 18.1 does not exist in us-east-1, which offers 18.3, 18.4 and 18.6). If us-east-1 rejects it, set the newest supported major and record the fallback in `openspec/changes/p1-aws-dev-env/progress.md`.
- Cognito clients are public (PKCE, code flow, no secret). Domain prefix must be unique; override `cognito_domain_prefix` if taken.
- Checkpoint objects are locked in governance mode for `checkpoint_retention_days` (1 by default), so `tofu destroy` of the bucket needs `s3:BypassGovernanceRetention` or waiting out the window.

## GitHub OIDC apply role (task 4.2)
`oidc.tf` creates the GitHub OIDC provider and `locksmith-dev-github-apply`. Its trust policy (`policies/github-apply-trust.json.tftpl`) allows only `aud = sts.amazonaws.com` and the single exact subject `repo:locksmith-hq/locksmith:environment:aws-base-apply`, so only the dispatched apply workflow job that runs in that GitHub environment (required reviewers, deployment branch limited to main) can assume it. The first apply of this role is done by the owner; after that the workflow can apply `base`. The role explicitly denies Organizations, Budgets, Cost Explorer, account, SSO and IAM role/provider changes, so CI cannot weaken the guardrails or its own trust. `python3 -I infra/tofu/policy/test_base_oidc.py` checks this offline.
