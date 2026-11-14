# Proposal: M4 Agent Guardrails

## Why

Agents read files and run shell commands when they debug. Without guardrails, they dump `.env`, run
`printenv`, paste output into context, or commit local settings files that contain allowlisted
credential commands. v5 §7.2 proposed shims. v6 implements them through the agents' own hook
systems. Those hooks are deterministic and run before the tool executes. v6 also fixes the "fake
exit 0" behaviour (docs/v6-review.md §1.4) and partially closes the "pasted into chat" residual
risk (§1.7).

## What Changes

- `smith hook <agent> <event>`: one Rust implementation (crate `ls-hooks`) that reads the agent's hook
  JSON on stdin and writes the agent's decision format on stdout. Agents covered: `claude-code`
  (PreToolUse, UserPromptSubmit), `cursor` (beforeShellExecution, beforeReadFile,
  beforeSubmitPrompt), `codex` (its hook/approval config).
- Rule set: block reading secret-bearing files (`.env*`, `*.pem`, `id_*`, `~/.aws/credentials`,
  `.npmrc` with tokens…), environment dumps (`printenv`, `env`, `export -p`, `set`,
  `/proc/*/environ`), `smith reveal`/`export` by agents, and staging of sensitive files. Each block
  gives a clear reason and the supported alternative.
- Prompt scan: a user prompt containing a vault secret (any encoding) is blocked before it reaches
  the model, and the user is told which key matched.
- `smith init`: one command that creates the binding, migrates `.env` into the vault, adds
  `.gitignore` entries, installs the pre-commit secret scanner, and wires the hooks for every
  detected agent into project settings. It is idempotent.
- `smith scan [--staged|PATH]`: scans for vault secrets and for high-confidence generic patterns
  (gitleaks rule subset).
- Minimal plugin manifests in `integrations/claude-code`, `integrations/cursor` and
  `integrations/codex` that call `smith hook`. Full packaging and marketplace listings come in track
  P1.

## Usable outcome

After `smith init`, a developer's Claude Code, Cursor or Codex session cannot cat `.env` or dump the
environment. It cannot commit secrets. A secret accidentally pasted into the prompt is stopped
before it reaches the model.

## Capabilities

### New Capabilities
- `agent-guardrails`: Pre-execution decisions on agent tool calls and prompts.
- `repo-protection`: Keeping secrets and sensitive local files out of version control.

### Modified Capabilities

## Out of scope

- Agents without hook support. Those rely on `smith session` + `smith run` + redaction.
- Server-side push protection. The docs guide users to enable GitHub/GitLab push protection.

## Impact

New crate `ls-hooks`, `smith init`, `smith scan`, `integrations/{claude-code,cursor,codex}` manifests.
