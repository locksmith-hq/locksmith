# Proposal: P4 SDKs and remote MCP setup

## Why

Teams that want to automate Locksmith from their own code (create agents and grants in CI, read the activity ledger into a SIEM, toggle MCP tools) have only `packages/control-plane-client`. That package is private, hand-written over `fetch`, and covers agents, grants and audit only. Every new control-plane route is added by hand, so it drifts from `services/control-plane/openapi.json`.

The remote Hub MCP (`m1-remote-mcp`) lets a person's assistant reach the cloud hub. Today no plugin or `smith init` path writes that remote entry: a user has to copy a URL and client id from docs into each agent's config by hand.

## What Changes

- **TypeScript SDK** `packages/sdk` (`@locksmith/sdk`, Apache-2.0). Types are generated from `services/control-plane/openapi.json` with `openapi-typescript` (already in the repo), and the runtime is `openapi-fetch`. A small hand-written layer adds bearer auth, RFC 9457 problem errors and paging helpers. It covers every operation in the spec, and a drift test fails when the spec changes without regenerating.
- **One client, not two:** `packages/control-plane-client` re-exports its types from the SDK and calls through the SDK client, so the hand-written `fetch` code is deleted and the web and desktop apps keep their current imports.
- **Remote Hub MCP setup:** `smith init --hub <url>` writes a remote (Streamable HTTP) MCP entry for each detected agent whose config supports remote MCP with OAuth. The entries come from `crates/smith-cli/src/agents.rs`, the same single source P3 extends. `smith doctor` reports the entry, and `integrations/generic-mcp` documents the remote URL and the pre-registered public client for any other client.
- A `just test sdk` recipe and a `docs/testing.md` row. An SDK smoke test runs against `just up`.

## Capabilities

### New Capabilities
- `sdks`: client libraries generated from the control-plane OpenAPI spec, kept in sync by a drift test, plus the remote Hub MCP entry that `smith init --hub` writes for supported agents.

### Modified Capabilities

## Impact

- New `packages/sdk`. `packages/control-plane-client` becomes a thin re-export over it.
- `crates/smith-cli/src/{agents,init_cmd,doctor_m4}.rs` (remote entry). Generated files under `integrations/*` are covered by the existing drift test (`UPDATE_INTEGRATIONS=1`).
- `justfile` (`test sdk` case, `sdk-gen`), `docs/testing.md`, `integrations/generic-mcp/README.md`.
- No change to secrets handling. The SDK never calls a value or material route. The Hub MCP entry holds a URL and a public client id only; the agent stores its OAuth token itself (`docs/research/remote-mcp-auth.md`).

## Out of scope

- SDKs in other languages (Python, Go, Rust). Phase 5 orders them by demand.
- Publishing to npm or any registry: release signing and publishing belong to P2.
- A gateway or agent-relay SDK: agents keep using `smith`, `locksmith-mcp` and the Agent MCP.
- Remote Agent MCP entries for container or CI agents with agent tokens (a follow-up once a token helper is verified per agent), and any web or desktop UI.

## Depends on

`m1-remote-mcp:contract` (the hub `/mcp` route, its OpenAPI and the remote-MCP research note). Group 4 edits `agents.rs` after `p3-agent-plugins`; if p3 has not merged when a worker reaches group 4, merge main first and keep both behaviours.
