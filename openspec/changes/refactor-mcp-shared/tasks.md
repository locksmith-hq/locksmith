# Tasks: refactor-mcp-shared

## 1. Gateway TTL cell [sonnet]
- [x] 1.1 Add `services/gateway/src/ttl.rs` with `MAX_CACHE_TTL` (10 s) and `TtlCell<T: Clone>` (`new` clamps, `get`, `get_or_fetch` stamping at fetch start, store only on `Ok` and non-zero TTL). Register the module in `lib.rs`. Unit tests: clamp, expiry at the TTL, error not cached, zero TTL stores nothing, stamp at fetch start (design decision 1).
- [x] 1.2 Rebuild `ClientsCache` (`mcp_clients.rs`) and `SettingsCache` (`mcp_settings.rs`) on `TtlCell`, keeping their `new`, trait impls and behaviour.
- [x] 1.3 [haiku] Replace `MAX_GRANT_TTL`, `MAX_REVOKED_TTL` and `MAX_SETTINGS_TTL` with `MAX_CACHE_TTL` in `grants.rs`, `relay.rs`, `main.rs` and the in-file tests that name them; move the doc text to the one constant. No assertion value changes.
- [x] 1.4 Verify: `cargo nextest run -p ls-gateway -E 'test(ttl) | test(grants) | test(mcp)'` and `rg -n 'MAX_(GRANT|REVOKED|SETTINGS)_TTL' services` prints nothing.

## 2. Control-plane store [sonnet]
- [ ] 2.1 Add `services/control-plane/src/mcp_store.rs` with `upsert_client` (name capped at 200 chars, `RETURNING revoked_at`, `revoked_at` never written), `layer_settings` and `all_settings` (design decision 2). Register it in `lib.rs`. Test (against the test database used by `tests/mcp.rs`): record twice per layer, one row, latest name, 200-char cap, `revoked_at` untouched.
- [ ] 2.2 Switch `record_client` and `overrides_for` in `mcp_tools.rs` to the store.
- [ ] 2.3 Switch `upsert_agent_mcp_client` and `agent_tool_settings` in `api/internal.rs`, and `list_tools` in `api/mcp.rs`, to the store; keep the agent read's `ORDER BY tool` and the response shapes.
- [ ] 2.4 Verify: `cargo nextest run -p ls-control-plane -E 'binary(mcp) | binary(mcp_tools) | binary(tenancy) | binary(tenant_lint) | binary(audit) | binary(openapi)'` and `rg -n 'INSERT INTO mcp_clients|FROM mcp_tool_settings' services/control-plane/src` lists only `mcp_store.rs`.

## 3. Shared tool helpers in ls-mcp-server [sonnet]
- [ ] 3.1 Add `rmcp` (`=3.11.0`, features `server`, `transport-streamable-http-server`, same as the services) to `crates/ls-mcp-server/Cargo.toml`; add `tool_from_def(&ToolDef) -> Tool` and `error_status(&CallToolResult) -> Option<u64>` with unit tests (output schema present and absent, status 401, 501, missing, not an error result). Check `Cargo.lock` has no new package.
- [ ] 3.2 Hub: replace `to_tool` in `control-plane/src/mcp_endpoint.rs` (keep the read-only annotation) and the status read in `mcp_tools.rs` `call_outcome`. Gateway: replace `to_tool` and the status read in `mcp_endpoint.rs` `call_outcome`. Each side keeps its own mapping; the gateway does not map 501 (design decision 4).
- [ ] 3.3 Verify: `cargo nextest run -p ls-mcp-server -p ls-gateway -p ls-control-plane -E 'test(mcp)'`; existing outcome and `tools/list` snapshot tests pass unchanged.

## 4. Audit append and bearer challenge [sonnet]
- [ ] 4.1 `services/gateway/src/audit.rs`: add `append_to(path, body, ok_statuses)` and make `post` (`&[200, 201]`) and `post_mcp_call` (`&[201]`) call it (design decision 5). Add one test per status class (accepted, `4xx`, `5xx`, unparsable body, transport unavailable) for both callers.
- [ ] 4.2 Add `bearer_challenge(token_presented, resource_metadata)` next to `bearer` in `services/control-plane/src/auth.rs`; unit test byte equality with today's four header values. Use it in `McpEndpoint::challenge` (hub) and in the gateway `unauthorized` (design decision 6). Leave `RMCP_MESSAGE_TARGETS` unchanged.
- [ ] 4.3 Verify: `cargo nextest run -p ls-gateway -E 'test(audit) | test(mcp)'` and `cargo nextest run -p ls-control-plane -E 'test(bearer) | binary(mcp_auth)'`.

## 5. Local verification [haiku]
- [ ] 5.1 `git diff origin/main --stat -- ':!openspec'` touches only the files named in the proposal's Impact; `cargo nextest run -p ls-mcp-server -p ls-gateway -p ls-control-plane` passes with no assertion edited in `services/gateway/src/relay/tests/mcp*.rs` or `services/control-plane/tests/mcp*.rs` (`git diff` on those paths shows no changed `assert`).
- [ ] 5.2 `just up`, then the MCP smoke test (call `/mcp` on the hub and the gateway without a token and with a bad one; compare the `WWW-Authenticate` headers with `origin/main`), `just apps-build`, then `just quick`.
