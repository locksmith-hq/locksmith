# Proposal: F0 dev harness

## Why
Every later change must be testable locally, and agents must be able to see inside the running system:
its database, logs, traces and metrics. Without that, bugs get found late, and agents spend tokens
guessing. This is the first change. It ships no product code.

## Usable outcome
- `just up` starts the local stack:
  - Postgres
  - Grafana LGTM: Loki, Tempo, Prometheus or Mimir, and an OTel collector
  - OpenBao, used as a dev KMS through its transit engine
  - WireMock as the mock upstream API
- `just down`, `just reset`, `just logs <svc>`, `just psql` and `just harness-check` work.
- When Claude Code opens the repo, it gets project-scoped MCP servers from `.mcp.json`:
  - Postgres MCP (read-only)
  - Grafana MCP, which covers Loki, Tempo and Prometheus
- The agent can query tables, search logs and read traces without help.
- `just harness-check` proves every service is healthy and every MCP endpoint answers.

## Out of scope
Product services (S1 onward), cloud environments, CI changes beyond running `harness-check` on Linux.

## Depends on
None.

## Impact
New: `infra/compose/`, `.mcp.json`, `justfile` recipes, `scripts/harness-check.sh`, and a docs page `docs/dev-harness.md`.
