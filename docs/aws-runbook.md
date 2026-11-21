# AWS dev environment runbook

Claude reads AWS through the read-only AWS MCP server (`aws` in `.mcp.json`, `awslabs.aws-api-mcp-server` pinned, `READ_OPERATIONS_ONLY=true`). It runs on the owner's machine with the `locksmith-readonly` profile (a read-only IAM role). It is never configured on the cloud VM, and Claude never holds AWS keys (A0-18).

Setup (owner, once): create the read-only role from the `base` stack outputs, add a `locksmith-readonly` profile to `~/.aws/config`, then check with `aws sts get-caller-identity --profile locksmith-readonly`. Adjust `AWS_REGION` in `.mcp.json` if the stack uses another region.

## Rules
- Claude may only describe, list and read logs. It never changes IAM, Organizations, SCPs, Budgets or Identity Center.
- Every mutating call needs owner approval after a change brief (below).
- Every resource Claude creates carries the tag `created-by=claude-mcp` (and `project=locksmith, env=dev`).
- Before the session ends, each such resource is imported into OpenTofu or destroyed. `just aws-drift` flags any `created-by=claude-mcp` resource OpenTofu does not manage.

## Change brief template
```
What:        <resources and the exact change>
Cost:        <idle and per-session estimate, with the price page>
Blast radius: <what else can be affected>
Security:    <IAM, network, data exposure; no secret values>
Rollback:    <exact steps; how it is destroyed or imported>
```

## Everyday commands
`just aws-up`, `aws-down`, `aws-status`, `aws-drift`, `aws-smoke`, `aws-validate`. They refuse to run without credentials and never print them.
