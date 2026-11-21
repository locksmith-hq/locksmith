# Design: P4 SDKs and remote MCP setup

## Context

- `packages/control-plane-client` already generates `src/schema.d.ts` with `openapi-typescript` 7.13 from `services/control-plane/openapi.json` (38 operations). Its runtime is hand-written `fetch` for agents, grants and audit only, and `apps/web` and `apps/desktop` import it.
- `services/control-plane/tests/openapi.rs` keeps `openapi.json` in sync with the Rust handlers, so the JSON file is the source of truth for clients.
- `m1-remote-mcp` adds the Hub MCP at `/mcp` on the control plane, with OAuth 2.1, PKCE and a documented pre-registered public client. `docs/research/remote-mcp-auth.md` (on the m1 branch) records how Claude Code and Codex store remote-MCP tokens; Cursor is unverified.
- `crates/smith-cli/src/agents.rs` is the single source for per-agent config paths and MCP entries, and P3 is extending it now.

## Goals / Non-Goals

**Goals:** one generated TypeScript SDK covering the whole control-plane API; delete the hand-written client code; a one-command remote Hub MCP setup for the agents that support it.

**Non-Goals:** other languages, registry publishing (P2), agent-token remote entries, and UI. See proposal "Out of scope".

## Decisions and evidence

| Decision | Alternatives rejected | Evidence |
|---|---|---|
| `openapi-typescript` types plus the `openapi-fetch` runtime | `openapi-generator` typescript-fetch (Java toolchain, large generated code); hand-written client (drifts, as it has) | openapi-fetch is about 6 kB and typed by the openapi-typescript output already in the repo: https://openapi-ts.dev/openapi-fetch/ ; npm `openapi-fetch` 0.17.0, MIT, modified 2026-06-15 (`npm view`, 2026-11-20) |
| SDK in `packages/sdk`; `control-plane-client` re-exports it | Two clients side by side | AGENTS.md: `packages/` holds shared TypeScript; the quality bar forbids duplicated code |
| Drift test regenerates into a temp dir and diffs | A CI-only check | Runs in `just test-web` and `just ci`, as the integrations drift test does today (`UPDATE_INTEGRATIONS=1`) |
| Remote entry only where the agent supports remote MCP with OAuth | A bearer token in the config file | Security rule: no secret in a file an agent can read. Claude Code and Codex store tokens in the keychain (remote-mcp-auth.md) |
| Remote entries generated from `agents.rs` | Hand-edited files per integration | P3 design: `agents.rs` is the single source, with the drift test |

## OSS used

| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| `openapi-fetch` | MIT | 0.17.0 (pin exact; re-check in task 1.1) | 2026-06 | Typed fetch runtime over the generated paths | Not AGPL; fine for an Apache-2.0 SDK |
| `openapi-typescript` | MIT | 7.13.0 (already a dev dependency) | see npm | Type generation | Not AGPL |

Built in-house: only the auth, problem-error and paging helpers (about 100 lines). We searched for and rejected: openapi-generator (Java), orval (React Query focused, heavier), and hey-api/openapi-ts (viable, but a second generator next to openapi-typescript adds nothing).

## How an agent debugs this

- `npm test --workspace packages/sdk` covers the drift, operation coverage, errors and the no-value-route check. `just test sdk` runs the same.
- `just up` then `just sdk-smoke`: the SDK lists, creates and deletes an agent against the local control plane, signed in with the Keycloak test user. Failures show in the control-plane logs in Grafana (Loki, `service=control-plane`) and in traces by `operationId`.
- `smith init --hub <url> --dry-run` prints the entries it would write; `smith doctor` shows the `hub.mcp` check per agent.

## Risks / Trade-offs

- openapi-fetch is pre-1.0, so minor bumps may break it. Mitigation: pin exactly; the drift and smoke tests catch breakage.
- Per-agent remote-MCP support changes fast. Mitigation: task 4.1 verifies each agent with sources, and an unsupported agent gets no entry.
- `agents.rs` conflicts with in-flight P3. Mitigation: group 4 comes last and merges main first.
