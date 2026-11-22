# Proposal: refactor-mcp-shared

## Why

The review of the merged m1-remote-mcp change (#494) found the same MCP helper written two or three times, once for the hub (control plane) and once for the gateway. One pair has already drifted. These are security-relevant paths (revoke checks, audit outcome, the 401 challenge), so each rule should live in one place.

| # | Duplicated code | Locations |
|---|---|---|
| a | Single-entry TTL cache (`Mutex<Option<(Instant, T)>>`, TTL clamped to 10 s, errors never cached, stamp at fetch start), plus the 10 s bound declared three times | `services/gateway/src/mcp_clients.rs` `ClientsCache` and `MAX_REVOKED_TTL`; `mcp_settings.rs` `SettingsCache` and `MAX_SETTINGS_TTL`; `grants.rs` `MAX_GRANT_TTL` |
| b | `mcp_clients` upsert SQL with the 200-char name cap, and the `mcp_tool_settings` read | `services/control-plane/src/mcp_tools.rs` `record_client` and `overrides_for`; `api/internal.rs` `upsert_agent_mcp_client` and `agent_tool_settings`; `api/mcp.rs` `list_tools` |
| c | `ToolDef` to rmcp `Tool`, and the audit outcome of a finished call | gateway `mcp_endpoint.rs` `to_tool` and `call_outcome`; hub `mcp_endpoint.rs` `to_tool` and `mcp_tools.rs` `call_outcome` |
| d | HTTP call plus status mapping to `AuditError` | `services/gateway/src/audit.rs` `post` and `post_mcp_call` |
| e | `401` plus `WWW-Authenticate: Bearer` challenge | gateway `mcp_endpoint.rs` `unauthorized`; hub `mcp_endpoint.rs` `unauthorized` and `McpEndpoint::challenge` |

The two `call_outcome` functions have already drifted: only the hub maps a tool error with status `501` to `error` with reason `not_available`. The gateway reports it as `tool_error`.

## What Changes

- Gateway: add a `ttl` module with one generic `TtlCell<T: Clone>` and one `MAX_CACHE_TTL` (10 s). `ClientsCache` and `SettingsCache` wrap the cell. `MAX_GRANT_TTL`, `MAX_REVOKED_TTL` and `MAX_SETTINGS_TTL` are replaced by `MAX_CACHE_TTL`.
- Control plane: add a `mcp_store` module that owns the `mcp_clients` upsert (with the name cap) and the `mcp_tool_settings` reads. The three call sites use it.
- `ls-mcp-server`: gains `tool_from_def(&ToolDef) -> rmcp::model::Tool` and `error_status(&CallToolResult) -> Option<u64>`. Both `to_tool` copies and both `call_outcome` copies use them. Each side keeps its own outcome mapping. The hub still adds its read-only annotation on top of the shared `Tool`.
- Gateway `audit.rs`: one `append_to(path, body, ok_statuses)` behind `post` and `post_mcp_call`.
- `ls-control-plane::auth`: one `bearer_challenge(token_presented, resource_metadata)` next to `bearer`, used by both `unauthorized` functions.
- There is no behaviour change. Whether the gateway should also map `501` is recorded as a decision in design.md and is not changed here.

Out of scope:
- Any change to revoke checks, fail-closed paths, audit events or their reason codes, TTL values, SQL semantics, HTTP bodies or headers.
- `RMCP_MESSAGE_TARGETS` and `cap_rmcp_logs`: left as they are (design decision 6).
- Making `GrantCache` (multi-entry, LRU) use `TtlCell`. Only its TTL constant is shared.
- Making the gateway map `501`; that needs its own change (design decision 4).

Depends on: none (m1-remote-mcp is merged).

Usable outcome: whoever next changes the revoke TTL bound, the client upsert, the audit outcome mapping or the 401 challenge edits one function, and both the hub and the gateway follow.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `remote-mcp`: one added requirement, that the MCP helpers have a single implementation shared by the hub and the gateway, with unchanged observable behaviour.

## Impact

- `services/gateway` (new `ttl.rs`; edits in `mcp_clients.rs`, `mcp_settings.rs`, `grants.rs`, `relay.rs`, `main.rs`, `mcp_endpoint.rs`, `audit.rs`), `services/control-plane` (new `mcp_store.rs`; edits in `mcp_tools.rs`, `api/internal.rs`, `api/mcp.rs`, `mcp_endpoint.rs`, `auth.rs`), `crates/ls-mcp-server`.
- `ls-mcp-server` gains an `rmcp` dependency pinned to the same `=3.11.0` and features the two services already use. Nothing new enters `Cargo.lock`.
- There are no API, data, schema or config changes.
