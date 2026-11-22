# Design: refactor-mcp-shared

## Context

See proposal.md, "Why". Each location was re-read on 2026-11-21 against `origin/main` before planning. Differences that the refactor must keep:

- The hub `to_tool` sets `tool.annotations = read_only(def.default_enabled)`. The gateway `to_tool` sets no annotations.
- The hub `unauthorized` builds its challenge from the endpoint (`Bearer [error="invalid_token", ]resource_metadata="<url>"`, falling back to bare `Bearer`). The gateway sends `Bearer error="invalid_token"` or bare `Bearer`. The response bodies differ too (`ApiError` on the hub, the relay `error()` on the gateway), and stay as they are.
- The hub `record_client` writes `principal = "<issuer>|<subject>"`, layer `hub`, and ignores `revoked_at`. The agent upsert writes `principal = client_id = agent id`, layer `agent`, and returns `revoked_at`.
- The three settings reads differ in shape: hub (`layer = 'hub'`, relies on RLS), agent (`org_id = $1 AND layer = 'agent' ORDER BY tool`), console list (all layers, `layer` column too).
- `post` appends `200 | 201`; `post_mcp_call` appends `201` only.
- Gateway `call_outcome` returns `McpOutcome`/`McpReason` enums; hub `call_outcome` returns `Code` strings with different reason names (`forbidden` vs `tool_error` for a 401/403).

## Goals / Non-Goals

**Goals:**
- One implementation per helper, each change point findable by grep.
- Identical observable behaviour: same TTL bound, same SQL effect, same outcome and reason per input, same header bytes.

**Non-Goals:**
- A shared audit or outcome vocabulary across hub and gateway.
- Touching `GrantCache` internals, or any TTL value.
- Moving gateway code into the control-plane crate or the reverse beyond what already exists (`ls_control_plane::auth::bearer`).

## Decisions

### 1. One generic `TtlCell<T: Clone>` in a gateway `ttl` module
`services/gateway/src/ttl.rs` holds `MAX_CACHE_TTL = 10 s` and `TtlCell<T>`: `new(ttl)` clamps to the max, `get()` returns the clone while `elapsed < ttl`, `async fn get_or_fetch(f)` returns the cached value or awaits `f`, stamps the entry with the time the fetch started, stores only on `Ok` and only when the TTL is non-zero. `ClientsCache` and `SettingsCache` keep their public API and trait impls and delegate to it. `MAX_GRANT_TTL`, `MAX_REVOKED_TTL` and `MAX_SETTINGS_TTL` are deleted and their users (`grants.rs`, `relay.rs`, `main.rs`, in-file tests) use `MAX_CACHE_TTL`. The constants' doc text (design decision 4 of m1: at most 10 s so a revocation takes effect within it) moves to the one constant. The cell lives in the gateway, not `ls-mcp-server`, because only the gateway caches and the crate has no async or time dependency.

### 2. A `mcp_store` module in the control plane, functions over the connection
`services/control-plane/src/mcp_store.rs` exposes, each taking the `with_org` connection and the org id:
- `upsert_client(c, org_id, layer, client_id, principal, name) -> Result<Option<OffsetDateTime>>`: the single `INSERT ... ON CONFLICT (org_id, layer, client_id, principal) DO UPDATE SET client_name, last_seen_at = now() RETURNING revoked_at`, with the 200-char cap applied inside. The hub ignores the returned value. `revoked_at` is still never written.
- `layer_settings(c, org_id, layer) -> Result<HashMap<String, bool>>` for the hub and agent reads, and `all_settings(c, org_id)` for the console list.

The hub read gains an explicit `org_id = $1` filter that it did not have. Row-level security already limits `with_org` connections to the org, so the result set is the same; the agent read already has both. The agent read's `ORDER BY tool` is kept for its API output order (ordering does not matter to the hub's map). The migration and the table are untouched.

### 3. Move `ToolDef -> Tool` and `error_status` into `ls-mcp-server`
`ls-mcp-server` already owns `ToolDef` and is a dependency of both services. It gains `tool_from_def(&ToolDef) -> rmcp::model::Tool` (name, description, input schema, output schema) and `error_status(&CallToolResult) -> Option<u64>` (the `/error/status` pointer on `structured_content`, only for `is_error == true`). The hub's `to_tool` becomes `let mut t = tool_from_def(def); t.annotations = ...; t`. The gateway's becomes a direct call. The crate adds `rmcp` with the exact pin and features the services use (`=3.11.0`, `server`, `transport-streamable-http-server`); `Cargo.lock` does not change. `ToolDef` stays free of rmcp types, so `tool_from_def` is a free function, not a method.

### 4. Each side keeps its outcome mapping; the gateway does not start mapping 501
The shared part is reading the status. The mapping from status to audit code stays local because the vocabularies differ (typed enums vs `Code` strings, `forbidden` vs `tool_error`). The `501` drift is real: a tool that answers `501` (not available in this deployment) audits as `error`/`not_available` on the hub and `error`/`tool_error` on the gateway. Recommendation: the gateway should map it too, but it needs a new `McpReason::NotAvailable` variant, a control-plane `mcp-calls` endpoint that accepts the new reason, and a decision on whether `not_available` is a documented reason in the audit spec. That changes what is written to the audit ledger, so it is not a pure refactor. This change keeps the current behaviour on both sides and records the gap; follow-up: add a roadmap or backlog line "gateway call_outcome maps 501" (owner decision: yes or no).

### 5. `append_to` in the gateway audit, with the accepted statuses as a parameter
`async fn append_to(&self, path: &str, body: Vec<u8>, ok: &[u16]) -> Result<Uuid, AuditError>` does the `internal_post_json` call, maps `Internal::Unavailable` to `AuditError::Unavailable` and any other transport error to `Rejected`, treats a status in `ok` as success (parsing `Appended`, parse failure is `Rejected`), `500..=599` as `Unavailable`, anything else as `Rejected`. `post` passes `&[200, 201]` and `post_mcp_call` passes `&[201]`. Body building and the `AuditUnavailable` guard stay where they are. This is the fail-closed mapping, so the existing audit tests must pass untouched and one new test covers each status class.

### 6. `bearer_challenge` next to `bearer`; leave `RMCP_MESSAGE_TARGETS` alone
`ls_control_plane::auth::bearer_challenge(token_presented: bool, resource_metadata: Option<&str>) -> HeaderValue` builds `Bearer`, then joins `error="invalid_token"` (when a token was presented) and `resource_metadata="<url>"` (when given) with `", "`, and falls back to `Bearer` if the value is not a valid header. Output is byte-identical to both current forms, which a unit test asserts for all four combinations. `McpEndpoint::challenge` on the hub and gateway `unauthorized` call it. The response bodies stay different.

`RMCP_MESSAGE_TARGETS` (`rmcp`, `rmcp::service`, `rmcp::transport`) is not replaced by a single `rmcp=info` directive. `EnvFilter` picks the most specific matching directive, so a user's `RUST_LOG=rmcp::service=trace` would beat a lone `rmcp=info` and put whole JSON-RPC messages, including an `issue_short_lived_credential` result, into the logs. The three explicit directives exist to prevent that, and the code comment says so. The list is three short strings; the cost is lower than the risk. Left unchanged.

### Decisions and evidence

| Decision | Alternatives rejected | Evidence |
|---|---|---|
| `TtlCell<T>` in the gateway, one `MAX_CACHE_TTL` | Put it in `ls-mcp-server` (no async or time need there); keep per-cache constants as aliases (three names for one bound is the problem) | `mcp_clients.rs:121-160` and `mcp_settings.rs:77-115` are line-for-line the same apart from the type; `grants.rs:123` repeats the 10 s |
| `mcp_store` functions over a connection | A repository struct holding `AppState` (the callers already sit inside `with_org` closures) | The three SQL sites in `mcp_tools.rs`, `api/internal.rs` and `api/mcp.rs` |
| Hub read gets an explicit `org_id` filter | Keep two query strings | RLS scopes `with_org` connections; the agent read already filters both ways |
| Share `error_status`, not the mapping | One shared `call_outcome` | Return types and reason names differ (`Code` vs `McpOutcome`/`McpReason`); a shared mapping would change audit reasons |
| Do not map 501 on the gateway here | Map it now | Changes audit ledger output and needs a new reason variant; not a refactor |
| One `bearer_challenge` with `Option<&str>` metadata | Two functions | Both formats are the same grammar with an optional second parameter |
| Keep `RMCP_MESSAGE_TARGETS` | Single `rmcp=info` directive | `EnvFilter` most-specific-match: `rmcp::service=trace` from `RUST_LOG` would win over `rmcp=info` |

## OSS used

| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| rmcp | Apache-2.0 | =3.11.0 | already in tree | `Tool`, `CallToolResult` types now also used by `ls-mcp-server` | compatible |

Nothing new enters `Cargo.lock`. Searched first: a generic TTL cache crate (`moka`, `cached`) would add a dependency for a 20-line single-slot cell with a stamp-at-fetch-start rule that those crates do not offer, and the grant cache already has its own bounded store. No crate packages the other helpers (they are tied to this repo's types and SQL).

## Risks / Trade-offs

- [A cache that outlives its TTL or caches an error would delay a revoke or keep a stale allow] → `TtlCell` unit tests: clamp to the max, expiry at the TTL, error not cached, zero TTL stores nothing, stamp taken at fetch start. The existing `mcp_revoke.rs` and `mcp_settings.rs` gateway tests run unchanged.
- [`append_to` loosens a status mapping and an audit write is lost or reported OK] → one test per status class (`200`, `201`, `4xx`, `5xx`, unparsable body, transport error) for both callers; status sets stay explicit at the two call sites.
- [The shared upsert changes `last_seen_at` or `revoked_at` handling] → `revoked_at` is only read. Control-plane `tests/mcp.rs`, `tests/tenancy.rs`, `tests/tenant_lint.rs` and `tests/audit.rs` run unchanged, plus a new store test that records twice and asserts one row, latest name, 200-char cap and untouched `revoked_at` for both layers.
- [Header drift in the challenge breaks MCP client discovery (`resource_metadata`)] → byte-equality unit test for all four combinations, and `tests/mcp_auth.rs` unchanged.
- [`ls-mcp-server` gains a heavier dependency] → same pinned crate and features already compiled for both services; no new build cost.

## Migration Plan

Code only, with no schema change and no deploy steps. Rollback is a revert. No flags.

## How an agent debugs this

- `cargo nextest run -p ls-mcp-server -p ls-gateway -p ls-control-plane -E 'test(mcp)'`
- Gateway: `services/gateway/src/relay/tests/mcp*.rs` (revoke, settings, short-lived). Control plane: `services/control-plane/tests/mcp.rs`, `mcp_auth.rs`, `mcp_tools.rs`.
- `just up`, then call `/mcp` on the hub and the gateway without a token and compare the `WWW-Authenticate` header to the one before the change.
- Logs: gateway and control-plane `tracing` output (Grafana/Loki MCP); the `mcp.call event not appended` warning shows audit failures.
- DB tables: `mcp_clients` (client_name, last_seen_at, revoked_at), `mcp_tool_settings` (layer, tool, enabled), the audit events table (`mcp.call` rows, written via `internal/v1/mcp/agent-calls`) (Postgres MCP, read-only).
