# @locksmith/agent

A thin client for agent code: it holds the agent's identity, never a secret value. Apache-2.0.
The framework adapters in `integrations/agent-*` build on it; the Python client mirrors the table in snake_case.

| TypeScript | Call | Returns |
|---|---|---|
| `createAgentClient({controlPlaneUrl, gatewayUrl, enrollmentSecret? \| token?, fetch?})` | `POST {controlPlaneUrl}/v1/agent-tokens` on first use | a client; defaults from `LOCKSMITH_CONTROL_PLANE_URL`, `LOCKSMITH_GATEWAY_URL`, `LOCKSMITH_ENROLLMENT_SECRET` |
| `listGrants()` | `GET {gatewayUrl}/v1/grants` | `Grant[]` (ids, names, mode, expiry, allowed origin) |
| `relay({secretId, version, method, url, headers?, body? \| bodyBase64?})` | `POST {gatewayUrl}/v1/relay` | the redacted upstream response |
| `mcpUrl` | none | `{gatewayUrl}/mcp` |
| `authorizedFetch` | any request to the gateway origin | adds `Authorization: Bearer` with the current token; refuses other origins |
| `pickAllowedTools(tools)`, `assertNoValueTools(tools)`, `ALLOWED_TOOLS` | none | the filtered tool list; throws on a value-shaped schema |
| `close()` | none | drops the token |

Errors are `AgentError {status, slug}`: the gateway's slugs or `unauthorized`, `bad_config`, `foreign_origin`, `transport`. No server or transport text.
The token is renewed 60 s before `expires_at` and once after a `401`; it is never logged, serialized or put in an error.
