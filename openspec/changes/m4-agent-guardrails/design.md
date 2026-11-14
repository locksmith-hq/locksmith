# Design: M4 Agent Guardrails

## Context
Hooks are deterministic, but a pattern check on shell strings can be bypassed. An agent can always
write `python -c "print(open('.e'+'nv').read())"`. So v6 treats guardrails as **friction plus
detection**, and the real prevention is that the secret is not in the agent's reach: M2 removes
`.env`, and M5–M8 delegate operations. Labels in docs and `--explain` reflect this.

## Goals / Non-Goals
**Goals:** block the common, accidental leak paths with zero false positives on normal dev work.
Stay fast (<20 ms per hook) and fail safe.
**Non-Goals:** a complete shell-language sandbox.

## Decisions

### D1. Single engine, thin adapters
`ls-hooks` exposes `decide(Event) -> Decision{allow|deny(reason, alternative)|ask}`. Each adapter maps
an agent's JSON schema in and out. Golden-file tests per agent pin the JSON shapes. When an agent
changes its schema, only its adapter changes.

### D2. Shell analysis
Parse with `tree-sitter-bash`. Check every command node, including those inside `$(...)`, pipes,
`sh -c` strings (parsed recursively, depth 3) and `xargs`, against the rules. If parsing fails or the
command is obfuscated (`eval`, base64 into sh), the decision is **ask** in Claude Code and Cursor,
not deny, and the event is logged. This avoids blocking legitimate complex commands while still
surfacing them to the human.

### D3. Secret-aware file rules
Beyond the filename patterns, a file read is denied when the file's content contains an active vault
secret. The hook asks the daemon `scan_path`, and the daemon returns key names only. This catches
`config/local.yml` holding a pasted key.

### D4. Prompt scan
UserPromptSubmit sends the prompt text to daemon `scan_text`, which returns matched key names. On a
match the hook blocks with "Your prompt contains the value of STRIPE_KEY; it was not sent." Without
the daemon (locked), the scan falls back to generic high-confidence patterns only.

### D5. Hook failure semantics
If `smith` is missing or crashes, Claude Code treats a non-zero exit other than 2 as non-blocking.
So the hook script is a tiny wrapper that exits 2 with "Locksmith hook unavailable, run smith
doctor" when the binary is not found. That makes the failure safe and visible.

### D6. `smith init`
Steps: detect the repo root, write `.locksmith.toml`, offer the `.env*` import (M1) and delete,
append `.gitignore` entries (`.env*`, `!.env.example`, `.claude/settings.local.json`,
`.locksmith/`), install `.git/hooks/pre-commit` (or append to husky/lefthook/pre-commit-framework
config when present), and write agent hook config into `.claude/settings.json`,
`.cursor/hooks.json` and `.codex/config.toml`. Every step is idempotent and shown as a diff before
applying. `--yes` is available for CI.

## Risks / Trade-offs
- False positives annoy users and train them to disable the tool. Mitigations: an `ask` fallback,
  allow rules in `.locksmith.toml`, and a telemetry counter of overrides (opt-in, M11).
