# Public and private boundary

This repository is public. Anything committed here is visible to everyone and stays in
history forever. Operating Locksmith as a hosted service happens in a separate private
repository. This page says what goes where and how the checks enforce it.

## What stays out of this repository

- Real cloud identifiers: AWS account, organization and OU IDs, SSO portal URLs, ARNs
  that carry a real account ID, state bucket names, database and Cognito endpoints.
- Credentials of any kind, including test keys that look real (they trip scanners).
- Production and billing infrastructure, tenant data and customer names.
- Premium or hosted-only code. Premium features plug into public traits or interfaces;
  their implementation lives in the private repository and this repository never imports it.
- Owner or staff personal email addresses.

Examples in code and docs use AWS's documented fake IDs (`123456789012`, `111122223333`).

## What may stay here

- Generic, reusable infrastructure code that takes every environment value as a variable
  (`infra/tofu/base`, `infra/tofu/session`). State and `-backend-config` values are passed at
  apply time, never committed.
- Design docs and decisions that describe behaviour, not identifiers.

## How the checks enforce it

| Check | Where | Catches |
|---|---|---|
| `scripts/public-check.sh denylist` | `just public-check`, CI | Regexes in `scripts/public-denylist.txt`: SSO portal URLs, ECR and RDS endpoints, Cognito pool IDs, state bucket names, personal email |
| `scripts/public-denylist.local` | your machine only (git-ignored) | Your real literal values, one per line: account IDs, directory IDs, hostnames |
| gitleaks | CI, `just public-check` | Secret-shaped strings in files and history |
| `.gitignore` | git | `*.tfstate`, `*.tfvars`, `*.tfplan`, `backend_override.tf`, `.env` |
| GitHub push protection | repository setting | Known token formats at push time |

Set up once per machine:

```bash
just install-hooks   # pre-push hook runs the denylist check
```

Then create `scripts/public-denylist.local` with your real identifiers. It is ignored by git,
so the values never reach the public tree.

## If something leaks anyway

1. Treat any exposed credential as compromised: rotate it first, then clean up.
2. Identifiers (account IDs and similar) are not secrets, but remove them in a follow-up PR and
   add a denylist rule so they cannot return. Rewriting public history is a last resort and
   cannot recall forks or clones.
3. Record what happened in the private repository, not here.
