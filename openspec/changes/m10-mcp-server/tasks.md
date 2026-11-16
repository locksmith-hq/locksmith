# Tasks

## 1. Server

- [ ] 1.1 `locksmith-mcp` with rmcp stdio, attestation as a daemon client, `list_keys`, `status`, `issue_token`, `explain_block`, and the binding resource. Verify: MCP Inspector session plus a JSON schema test asserting no value fields. Partial: `locksmith-mcp` (hand-rolled stdio JSON-RPC, not rmcp) serves `list_keys` (lease-scoped `LeaseKeys`), `status`, `issue_token`, `explain_block` and the binding resource; the daemon serves `Role::Mcp` only those requests; schema test passes. Not done: MCP Inspector session, live-daemon e2e, packaging `locksmith-mcp` beside `locksmithd` so it is pinned.
- [ ] 1.2 Human prompt helper (design D1) with platform backends. Verify: manual checklist on macOS and Linux, plus a unit test of the TTY fallback.
- [ ] 1.3 `request_secret` and `rotate_secret` with the untrusted-text rendering and rate limit (design D2). Verify: e2e with a scripted prompt backend for approve, decline and the fourth-request error.

## 2. Integrations

- [ ] 2.1 Add the MCP config to `integrations/claude-code`, and snippets for `cursor` and `codex`. `smith init` wires them. Verify: `claude mcp list` shows locksmith after `smith init`. (progress: MCP wiring in agents.rs + init, integrations files, dev-install bundles locksmith-mcp; `claude mcp list` check pending)

## 3. Adversarial

- [ ] 3.1 **Gate A7**: live Claude is asked to obtain a key value through every MCP tool. Verify: `run.sh A7 --agent claude` gives zero hits.
