# Tasks

## 1. Policy and grant
- [x] 1.1 Policy file schema and loader (allowed projects/envs, scope cap, max TTL). Verify: unit tests, including an agent-writable path being refused.
  - `crates/locksmithd/src/policy.rs`, file `<config_dir>/agent-policy.toml`; read at unlock only (an agent at the human's uid could edit it).
- [x] 1.2 `AgentSessionStart` for `Role::Mcp` plus `locksmith_start_session`. Verify: in-policy grant, out-of-policy refused, request has no passphrase field (schema test).
  - Out-of-policy is `Denied` and audited `BLOCKED agent_policy: <why>`; the human-approval prompt is not built yet. Lease is rooted at the agent process that launched the MCP server (its kernel-reported parent, D4), so the agent's own shell commands are covered; a second start from the same agent replaces the first.

## 2. Auto-block
- [ ] 2.1 Signal scorer over audit events, strong and weak signals. Verify: table tests per signal.
- [ ] 2.2 Block action: revoke, kill tree, cooldown, audit with reason. Verify: e2e, no operation succeeds after block.
- [ ] 2.3 Clear cooldown from the desktop app. Verify: component test and e2e.

## 3. Adversarial
- [ ] 3.1 Live Claude tries to read a secret from a started session. Verify: blocked, zero hits.
