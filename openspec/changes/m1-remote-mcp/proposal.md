# Proposal: M1 remote MCP (Hub and Agent)

## Why
Today the only MCP server is `locksmith-mcp`, a stdio server on the developer's machine. A person using Claude, ChatGPT or Cursor against the cloud hub, and an agent running in a container or CI job, cannot reach Locksmith through MCP at all. Decision H1-2 sets the rule for any MCP tool: none returns a stored secret value. This change adds the two remote servers described in `docs/design/hub-technical-design.md` section 6, with one server-enforced switch per tool, so those clients can use Locksmith without ever holding a credential.

## What Changes
- **Hub MCP**: Streamable HTTP route `/mcp` on the control plane. A person signs in with OAuth 2.1 + PKCE against the same OIDC issuer; the assistant acts with exactly that person's permissions. Read tools on by default (list projects, list secret names and versions, read activity, list agents and grants, explain a block); mutating tools off by default.
- **Agent MCP**: Streamable HTTP route `/mcp` on the gateway. An enrolled agent signs in with its existing 15-minute agent token. Default-on tools: list my keys, relay an HTTP request, explain a block. `issue_short_lived_credential` is off by default (H1-2's one exception) and every issue is an audit event.
- **Tool switches**: table `mcp_tool_settings` (one row per org, layer and tool), enforced server-side: a tool that is off is neither listed nor callable.
- **Clients**: table `mcp_clients` records each connected client (layer, principal, name, last call, revoked); a person can revoke one.
- **Audit**: every MCP call is an event in the existing ledger (no new log table), carrying ids, tool name and outcome only.
- **Console and desktop**: a Clients page (connected clients, revoke) and a Tools page (one switch per tool) in `apps/web` and `apps/desktop`.
- A research note on remote MCP authorization (client registration, token audience, how agent tools store a token) is task 1.1, because the design doc leaves that unverified.

## Capabilities
### New Capabilities
- `remote-mcp`: the Hub and Agent MCP servers, tool switches, client records and the no-secret-value rule.

### Modified Capabilities
<!-- agent-connector and audit-ledger gain scenarios when this lands; recorded in the delta below as ADDED requirements of remote-mcp only, to keep the delta self-contained. -->

## Impact
`services/control-plane` (route `/mcp`, migrations 0012+ for `mcp_tool_settings` and `mcp_clients`, new admin endpoints, OpenAPI), `services/gateway` (route `/mcp`), `crates/` (a shared `ls-mcp-server` crate for tool registry, switch check and the no-value schema test), `packages/control-plane-client`, `apps/web`, `apps/desktop`, `tests/` (adversarial no-value cases), `docs/research`.

## Out of scope
Policy-based approvals (T2, T4: approve or deny request tools are added when those land), notifications (N1), the local stdio `locksmith-mcp` (unchanged), SDKs and agent-framework plugins (P3), MCP resources and prompts beyond tools, rate limiting beyond what the gateway already does.

## Depends on
`t1-human-auth:contract` (the OIDC issuer and the JWT-verifying middleware). The gateway side builds on archived S3/S4 work already on main.
