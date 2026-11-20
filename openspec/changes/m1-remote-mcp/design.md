# Design: M1 remote MCP

## Context
`crates/locksmith-mcp` is a hand-rolled stdio JSON-RPC server (seven tools, with a `schemas_carry_no_value_field` test). The control plane verifies human JWTs through JWKS (T1) and the gateway verifies 15-minute EdDSA agent tokens with audience `gateway`. `docs/design/hub-technical-design.md` section 6 defines the layers, tool lists and decisions D-2 / H1-2. The design says the MCP servers start as routes inside the existing binaries, not new deployments.

## Decisions and evidence
| Decision | Alternatives rejected | Evidence |
|---|---|---|
| `/mcp` route inside `control-plane` (Hub) and `gateway` (Agent), Streamable HTTP | Separate deployments; SSE transport | Hub design section 6; Streamable HTTP is the current MCP remote transport (https://modelcontextprotocol.io/specification) |
| Use the official Rust SDK `rmcp` for protocol and transport | Extending the hand-rolled stdio JSON-RPC | The existing code's own shortcut comment names `rmcp`; crates.io shows 3.11.0 updated 2026-11-17. Task 1.2 spikes it against axum before committing |
| Shared crate `ls-mcp-server`: tool registry, switch check, no-value schema test, audit hook | Duplicating per service | Both servers need identical rules; one test guards both |
| Hub sign-in: OAuth 2.1 + PKCE with the existing OIDC issuer, protected-resource metadata per the MCP authorization spec | A Locksmith-specific token | Hub design section 3.2; details settled by the research note (task 1.1) |
| Switches in `mcp_tool_settings`, checked on every list and call | Client-side hiding | Hub design section 6: "a client cannot list or call a tool that is off" |
| Calls recorded in the existing audit ledger | New MCP log table | Hub design section 6; one ledger |
| `issue_short_lived_credential` ships off by default and in its own task | Omit it | Decision H1-2 names it as the one exception |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| rmcp | Apache-2.0 (verify in task 1.2) | 3.11.0 (pin on add) | 2026-11-17 | MCP protocol, Streamable HTTP server | permissive, fine |
| existing: axum, jsonwebtoken/JWKS stack from T1 | per repo | repo versions | n/a | transport and token verification | already in use |
Versions and licences are re-checked and recorded when added (task 1.2).

## Built in-house
The tool registry, switch enforcement, audit hook and the no-value test, because they carry Locksmith's rules; the protocol layer is reused (rmcp).

## Architecture
Request -> axum `/mcp` -> auth layer (person JWT on the hub, agent token on the gateway) -> `ls-mcp-server` registry (filters by `mcp_tool_settings`) -> tool handler calling the same service functions the console or relay already use -> audit event. `mcp_clients` is upserted on `initialize`. Tool handlers return ids, names, metadata and relay results only.

## How an agent debugs this
`just up` (with the auth profile); `curl` or the MCP Inspector against `http://localhost:<port>/mcp`; logs via the Grafana/Loki MCP and `docker compose logs control-plane gateway`; traces in Tempo per tool call; DB tables `mcp_tool_settings`, `mcp_clients`, `audit_events` via the postgres MCP (read-only); `cargo nextest run -p ls-mcp-server`.

## Client binding for revoke
A session id is not enough: a revoked client could send a fresh `initialize` and keep working on a still-valid token. Revoke binds to something the client cannot mint again:
- **Hub:** the OAuth `client_id` (from dynamic registration or pre-registration) is carried in the access token and checked on every call, including `initialize`. `mcp_clients` is keyed by `(org, layer, client_id, principal)`. Revoking marks `revoked_at` and, at the issuer, revokes that client's refresh tokens and the person's consent for it, so consent is required again. A token is refused when its `auth_time` (the time the person last signed in) is before `revoked_at`; a refresh keeps `auth_time`, so it cannot mint a usable token, while a fresh sign-in with new consent can. Refusing by `iat` is not enough, because a refresh after the revoke mints a fresh `iat`. A token without `auth_time` is refused. Task 4.1 verifies that Keycloak keeps `auth_time` on refresh; if it does not, the strict rule applies: every token for that `client_id` and person is refused until an admin un-revokes ([#493](https://github.com/locksmith-hq/locksmith/issues/493), option A).
- **Agent:** the agent token has no client id, so revoke is per agent: the revoked agent's tokens are refused by the existing agent revocation (T8 makes it take effect in seconds); `mcp_clients` rows for it are marked revoked.
- The `Mcp-Session-Id` is only a transport convenience and is never trusted for authorization.
Task 4.2's test revokes a client, then re-initializes and calls a tool, and asserts `401` each time. The research note (task 1.1) confirms how `client_id` reaches the token for real clients.

## Open questions
- Remote MCP authorization: client registration (dynamic vs pre-registered), token audience, and how each agent tool stores a token. Unverified; resolved by the research note in task 1.1. If it needs an owner decision, the lead raises it before group 4.
- Which Hub mutating tools ship now: revoke grant and pause agents only if T8 has not landed yet are stubbed behind the switch; otherwise they call the T8 API.
