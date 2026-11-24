# Design: B2 Rust core service

## Context

Split out of `b1-nestjs-api` (design: `openspec/changes/b1-nestjs-api/design.md`, "Rust boundary"). Owner decision OC-9 G1 fixes what the core holds: audit append and checkpoint signing, agent-token and workload-token mint and verify, DEK wrap and unwrap through KMS (OpenBao transit locally). The code for each already exists in `services/control-plane/src` (`audit.rs`, `checkpoint.rs`, `agent_token.rs`, `workload.rs`, `kms.rs`) on top of `ls-audit` and `ls-envelope`.

## Decisions and evidence

| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | Contents exactly as OC-9 G1; authorization decisions are not in the core | Keep the policy engine in Rust | `openspec/decisions.md` OC-9 |
| 2 | A separate service `services/core`, package `ls-core-service` | Name it `ls-core`; extend the control plane | `crates/ls-core` already exists (exit codes, config paths); the control plane is being strangled by B1 |
| 3 | axum and utoipa, the same stack and OpenAPI generation as `services/control-plane` | gRPC/tonic | One HTTP stack in the workspace; the TypeScript client is generated the same way as `packages/control-plane-client` |
| 4 | Move code, do not rewrite it; shared code goes to a library crate both services use | Copy the modules | No behaviour change; one implementation to review |
| 5 | Caller authentication: a shared service token (`LOCKSMITH_CORE_SERVICE_TOKEN`, `Authorization: Bearer`, constant-time compare, required at startup, 401 on everything but `/healthz` and `/readyz`) | mTLS | Same mechanism as the control plane's gateway service token (`auth.rs` `ServiceToken`); one secret on an internal-only network needs no PKI. mTLS can layer on later without changing the API |

## OSS used

No new packages: axum, utoipa, sqlx, tokio and the OpenAPI client generator are already used by `services/control-plane` and `packages/control-plane-client` (same versions, same licences, not AGPL). A task that adds a package records it here with licence, version and release date.

Built in-house: nothing new; the service is assembled from existing modules.

## How an agent debugs this

- MCP servers in `.mcp.json`: `grafana` for the core's logs (Loki) and traces (Tempo); `postgres` (restricted) for the audit tables.
- Commands: `just up`, `just core-check`, `cargo nextest run -p ls-core-service`, `just leak-scan`.
- Tables: the audit tables written by `ls_audit::pg`.

## Risks

- Moving key-handling code is security-sensitive: no behaviour change, and the existing control-plane tests must stay green after each move.
- The core is reachable only on the internal network; a test asserts an unauthenticated caller is refused.
