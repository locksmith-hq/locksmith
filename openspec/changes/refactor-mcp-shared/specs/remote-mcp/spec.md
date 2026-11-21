## ADDED Requirements

### Requirement: MCP helpers have a single implementation shared by hub and gateway
The cache bound on revocation-relevant reads, the `mcp_clients` upsert and `mcp_tool_settings` reads, the tool definition to MCP tool conversion, the tool-error status reader, the audit append call and the bearer challenge SHALL each have one implementation, used by every Hub MCP and Agent MCP code path that needs it. Sharing SHALL NOT change any observable behaviour: revoke checks, fail-closed paths, audit events and reason codes, response bodies and headers stay as they were.

#### Scenario: Cache bound is one value
- **WHEN** a gateway cache for grants, tool switches or revoked clients is built with a TTL above 10 s
- **THEN** it serves an entry for at most 10 s, an error read is never cached, and a zero TTL disables caching, as before

#### Scenario: Revoke still takes effect within the bound
- **WHEN** a client is revoked while the gateway holds a cached revoked set
- **THEN** the next request after the cache expires is refused, and an unreadable registry still counts as revoked (fail closed)

#### Scenario: Client upsert is the same for both layers
- **WHEN** a hub client or an agent client is recorded twice with different names
- **THEN** one row exists with the latest name capped at 200 characters, `last_seen_at` refreshed and `revoked_at` untouched

#### Scenario: Audit outcome is unchanged
- **WHEN** a tool call finishes with `ok`, a `401` or `403` tool error, another tool error, or a protocol error, on the hub or on the gateway
- **THEN** the `mcp.call` outcome and reason are the same as before the change on each side

#### Scenario: Challenge header is byte-identical
- **WHEN** a request reaches `/mcp` on the hub or the gateway without a token, or with an invalid one
- **THEN** it is answered `401` with the same `WWW-Authenticate` value as before

#### Scenario: Existing tests pass unchanged
- **WHEN** the gateway MCP tests (`services/gateway/src/relay/tests/mcp_*.rs`) and the control-plane MCP tests (`tests/mcp.rs`, `tests/mcp_auth.rs`, `tests/mcp_tools.rs`) run after the change
- **THEN** they pass with no assertion edited
