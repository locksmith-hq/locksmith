# Progress: refactor-mcp-shared

<!-- append-only session log -->

## 2026-11-21 · planner · planned
- Planned from the verified review findings of the merged m1-remote-mcp change (#494): duplicated TTL cache, `mcp_clients` upsert and settings reads, `to_tool`, `call_outcome`, audit append block and bearer challenge.
- Recorded in design.md: the gateway does not map `501` in this change (audit-visible, needs an owner decision), and `RMCP_MESSAGE_TARGETS` stays because one `rmcp=info` directive would lose to `RUST_LOG=rmcp::service=trace`.

## 2026-11-21 worker (alfie)
- Task: 1.1-1.4, 3.1-3.3, 4.1-4.3 - done
- Verified: `cargo nextest run -p ls-gateway -E 'test(ttl) | test(grants) | test(mcp)'` (62 pass), `-p ls-mcp-server -p ls-gateway -p ls-control-plane -E 'test(mcp)'` (76 pass), audit/bearer/mcp_auth (91 pass); `rg MAX_(GRANT|REVOKED|SETTINGS)_TTL services` empty; Cargo.lock only gains the rmcp edge on ls-mcp-server (no new package).
- Notes for next session: group 2 (control-plane `mcp_store`, needs the test DB, so start dockerd) and group 5 (diff scope, `just up` smoke, `just quick`) remain. Parked d2-aws-sts: its open tasks 5.1/5.2/7.2 need the console bindings page from t3-console-mvp (PR #489, not merged).
