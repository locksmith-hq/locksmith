# Progress: refactor-mcp-shared

<!-- append-only session log -->

## 2026-11-21 · planner · planned
- Planned from the verified review findings of the merged m1-remote-mcp change (#494): duplicated TTL cache, `mcp_clients` upsert and settings reads, `to_tool`, `call_outcome`, audit append block and bearer challenge.
- Recorded in design.md: the gateway does not map `501` in this change (audit-visible, needs an owner decision), and `RMCP_MESSAGE_TARGETS` stays because one `rmcp=info` directive would lose to `RUST_LOG=rmcp::service=trace`.
