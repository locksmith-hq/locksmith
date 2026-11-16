# Tasks

## 1. Framework

- [ ] 1.1 `smith integrations ls|install|update|doctor` with agent detection and `compat.toml`. Verify: e2e with fake agent installs in a temp HOME.
- [ ] 1.2 Contract test kit: golden payloads per agent version and the weekly latest-agent job. Verify: the job runs green, and a mutated fixture fails it.

## 2. Wave 1 (after M4/M10)

- [ ] 2.1 Claude Code plugin plus a marketplace repo, slash commands, the skill, SessionStart status. Verify: `claude plugin install` from the marketplace and an A6/A7 live run.
  - Progress: Claude Code plugin manifest, root marketplace.json, 7 skills and /status, /keys commands added and `claude plugin validate --strict` passes. Still open: `claude plugin install` from a published marketplace, A6/A7 live run, SessionStart status.
- [ ] 2.2 Cursor and Codex packages. Verify: A6 scripted runs per agent.
- [ ] 2.3 VS Code extension (TS, npm) published to the Marketplace and Open VSX. Verify: `@vscode/test-electron` tests, plus a status bar e2e against the mock daemon.

## 3. Wave 2

- [ ] 3.1 Gemini CLI extension, Grok Build integration (verify current hook/MCP docs first), OpenHands microagent. Verify: A6 per agent where hooks exist, and an MCP smoke test otherwise.
- [ ] 3.2 Devcontainer feature with socket forwarding (attestation note: a containerised client is attested by the forwarding shim on the host). Verify: devcontainer CLI e2e push.
- [ ] 3.3 GitHub Action. Verify: a workflow in this repo uses it to run an integration test with a redacted secret.
