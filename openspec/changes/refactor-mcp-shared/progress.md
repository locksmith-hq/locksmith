# Progress: refactor-mcp-shared

<!-- append-only session log -->

## 2026-11-21 · planner · planned
- Planned from the verified review findings of the merged m1-remote-mcp change (#494): duplicated TTL cache, `mcp_clients` upsert and settings reads, `to_tool`, `call_outcome`, audit append block and bearer challenge.
- Recorded in design.md: the gateway does not map `501` in this change (audit-visible, needs an owner decision), and `RMCP_MESSAGE_TARGETS` stays because one `rmcp=info` directive would lose to `RUST_LOG=rmcp::service=trace`.

## 2026-11-21 worker (alfie)
- Task: 1.1-1.4, 3.1-3.3, 4.1-4.3 - done
- Verified: `cargo nextest run -p ls-gateway -E 'test(ttl) | test(grants) | test(mcp)'` (62 pass), `-p ls-mcp-server -p ls-gateway -p ls-control-plane -E 'test(mcp)'` (76 pass), audit/bearer/mcp_auth (91 pass); `rg MAX_(GRANT|REVOKED|SETTINGS)_TTL services` empty; Cargo.lock only gains the rmcp edge on ls-mcp-server (no new package).
- Notes for next session: group 2 (control-plane `mcp_store`, needs the test DB, so start dockerd) and group 5 (diff scope, `just up` smoke, `just quick`) remain. Parked d2-aws-sts: its open tasks 5.1/5.2/7.2 need the console bindings page from t3-console-mvp (PR #489, not merged).

## 2026-11-21 worker (alfie)
- Task: 2.1-2.4, 5.1 - done
- Verified: `cargo nextest run -p ls-control-plane -E 'binary(mcp_store) | binary(mcp) | binary(mcp_tools) | binary(tenancy) | binary(tenant_lint) | binary(audit) | binary(openapi)'` (57 pass); `cargo nextest run -p ls-mcp-server -p ls-gateway -p ls-control-plane` (400 pass); no assert edited in the mcp test paths; `rg` lists only mcp_store.rs; `just quick` clean.
- Notes for next session: only 5.2 remains (`just up` smoke comparing WWW-Authenticate on hub and gateway with origin/main, `just apps-build`); both are heavy (Keycloak profile, Tauri build), so give them a run of their own. `layer_settings` returns an ordered Vec (not a HashMap as design.md says) because the agent read needs `ORDER BY tool`; the hub collects it into a map.
