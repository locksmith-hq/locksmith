# Tasks

## 1. Decision engine (`ls-hooks`)

- [ ] 1.1 Rule model and `decide()`, with filename patterns and env-dump rules. Verify: a table-driven test with 200 commands (100 must-deny, 100 must-allow from real dev sessions).
- [ ] 1.2 tree-sitter-bash analysis with nested `sh -c` and the ask fallback (design D2). Verify: tests for pipe, subshell, `sh -c`, `eval` and base64 obfuscation.
- [ ] 1.3 Daemon ops `scan_path` and `scan_text` (return key names only) plus their wiring. Verify: the content-match deny test, and a protocol schema test (no values).

## 2. Agent adapters and manifests

- [ ] 2.1 Claude Code adapter (PreToolUse for Bash/Read/Grep/Edit, UserPromptSubmit) with golden JSON fixtures, plus `integrations/claude-code/hooks/hooks.json` and the wrapper script (design D5). Verify: `claude -p` e2e in CI where `cat .env` is blocked.
- [ ] 2.2 Cursor adapter plus `integrations/cursor/hooks.json`. Verify: golden fixture tests.
- [ ] 2.3 Codex adapter plus `integrations/codex/` config snippet. Verify: golden fixture tests.

## 3. Repo protection

- [ ] 3.1 `smith scan` with vault-aware and generic rules (gitleaks subset, high confidence only). Verify: a fixtures test with zero false positives on a corpus of 5 popular OSS repos.
- [ ] 3.2 Pre-commit installer with husky, lefthook and pre-commit-framework detection. Verify: e2e per hook manager.
- [ ] 3.3 `smith init` orchestration with a diff preview, idempotency and `--yes`. Verify: e2e runs twice with no changes, plus a snapshot of the preview.

## 4. Diagnostics and adversarial

- [ ] 4.1 Doctor checks `hooks.claude_code`, `hooks.cursor`, `hooks.codex` (installed, version matches) and `repo.precommit`. Verify: snapshots.
- [ ] 4.2 Adversarial A6 (scripted plus live Claude): cat .env, printenv, Read tool, stage the settings file, paste a secret in the prompt, commit a secret. Verify: `run.sh A6 --agent claude` gives an oracle with zero hits.

## 5. Milestone acceptance

- [ ] 5.1 Run `smith init` on 3 real repos (Node, Python, Rust) and use Claude Code for a day. Record every false positive in the PR. Verify: the false-positive count is ≤ 2 and each one is fixed or has a ticket.
