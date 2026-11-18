# Tasks: S4 agent connector

## 1. Agent identity and grants in the control plane [opus]
- [x] 1.1 Migration and API for `agents` and `agent_grants` (org_id, RLS, FORCE RLS, UUIDv7); enrollment secret shown once, stored hashed; `openapi.json` updated.
- [x] 1.2 Token mint endpoint (EdDSA JWT, 15 min, aud `gateway`), JWKS endpoint, internal grants lookup endpoint behind the service token.
- [x] 1.3 Verify: `cargo nextest run -p ls-control-plane` covers cross-org isolation, expired token, wrong audience, one-time enrollment secret, no secret field in any response schema.

## 2. Gateway auth and grant enforcement [opus]
- [x] 2.1 Replace the static caller token with JWT verification via JWKS (cached, rotation by kid); add `GET /v1/grants`.
- [x] 2.2 Enforce grant (and expiry) before unwrap; write `agent_id` into `gateway_audit`; audit denials.
- [ ] 2.3 Verify: `cargo nextest run -p ls-gateway` covers forged, expired and wrong-audience tokens, no grant makes no decrypt call, revoked grant stops within the cache TTL.

## 3. smith and MCP remote mode [sonnet]
- [ ] 3.1 `smith login --agent`, `smith grants`, `smith relay` against the gateway; token kept in a 0600 state file; output redacted.
- [ ] 3.2 `locksmith-mcp` tools `list_grants` and `relay_request` using the remote backend; local-vault behaviour unchanged.
- [ ] 3.3 Verify: `cargo nextest run -p smith-cli -p locksmith-mcp`.

## 4. Console and desktop surface [sonnet]
- [ ] 4.1 Web page listing agents and grants with create/revoke; types generated from `openapi.json`.
- [ ] 4.2 `apps/desktop` agents and grants view (reads the same API through the Tauri frontend; list, create, revoke).
- [ ] 4.3 Verify: `npm run lint` and `just apps-build` (web and desktop).

## 5. Demo and e2e [sonnet]
- [ ] 5.1 Compose wiring and `just connector-smoke`: register agent, grant a canary secret, relay to the mock upstream through `smith` and the MCP tool; assert upstream saw it, the agent did not.
- [ ] 5.2 Live headless `claude -p` run calling the mock upstream (and a real API such as Langfuse when a key is available to the owner's setup) through the MCP tools; `just leak-scan` on the transcript, DB, Loki and Tempo; planted canary still detected.
- [ ] 5.3 Verify: `just up && just connector-smoke && just leak-scan`.

## 6. Local verification
- [ ] 6.1 `just up`, `just connector-smoke`, `just apps-build`, then `just ci`.
