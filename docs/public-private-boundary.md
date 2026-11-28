# Public and private boundary

This repository is public. Anything committed here is visible to everyone and stays in
history forever. Operating Locksmith as a hosted service happens in a separate private
repository. This page says what goes where and how the checks enforce it.

## What stays out of this repository

- Real cloud identifiers: AWS account, organization and OU IDs, SSO portal URLs, ARNs
  that carry a real account ID, state bucket names, database and Cognito endpoints.
- Credentials of any kind, including test keys that look real (they trip scanners).
- All AWS infrastructure code (OpenTofu stacks, apply and session scripts, runbooks, cost docs),
  production and billing infrastructure, tenant data and customer names. It lives in `locksmith-cloud`
  (owner decision 2026-11-22).
- The hosted service's own code and operations: the license server, billing, the plan catalog and SaaS-only
  features. Paid features of any kind, hosted or self-hosted, are private too (owner decision 2026-11-28,
  replacing the `ee/` layer): console pages, API modules and Rust code that belong to a paid plan.
- Owner or staff personal email addresses.

Examples in code and docs use AWS's documented fake IDs (`123456789012`, `111122223333`).

## What may stay here

- The seams paid features plug into, and their free defaults: `crates/ls-entitlements`, `apps/api/src/paid.ts`,
  `apps/web/src/console/paid.ts`, and the kit's plan badge and upgrade notice. The names of paid features and
  the plan each needs may appear here; their code, prices and limits may not.
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
