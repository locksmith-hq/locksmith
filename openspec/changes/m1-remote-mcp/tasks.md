# Tasks: M1 remote MCP

## 1. Contract and foundations [sonnet]
- [x] 1.1 [haiku] Write `docs/research/remote-mcp-auth.md`: the MCP authorization spec, client registration, token audience, and how Claude, Cursor and Codex store a remote-MCP token, each point with a source URL; also how a call is tied to an `mcp_clients` row (the OAuth `client_id` in the token, since a session id alone can be re-created); end with a recommendation for the Hub sign-in.
- [x] 1.2 Spike `rmcp` Streamable HTTP inside an axum route; record the licence, pinned version and release date in design.md "OSS used".
- [x] 1.3 Add `crates/ls-mcp-server` with the tool registry type, the default on/off table for both layers, and the no-value schema test (fails if any input or output schema has a value-like field).
- [x] 1.4 Add migration for `mcp_tool_settings` and `mcp_clients` (org-scoped, covered by the tenant lint) and the OpenAPI for list and update of tool settings and list and revoke of clients; regenerate `packages/control-plane-client` types and add fixture data.
- [x] 1.5 Verify: `cargo nextest run -p ls-mcp-server && npm test --workspace packages/control-plane-client`.

## 2. Hub MCP [sonnet]
- [x] 2.1 `/mcp` route on the control plane with OIDC token auth, `401` with `WWW-Authenticate` and protected-resource metadata; tests for missing, expired and wrong-audience tokens.
- [ ] 2.2 Read tools: list projects, list secret names and versions, read activity, list agents and grants, explain a block; each calls the existing service code as the person.
- [x] 2.3 Switch enforcement on list and call, and `mcp_clients` upsert on initialize; tests for off-tool hidden and refused.
- [x] 2.4 Off-by-default mutating tools: revoke a grant and pause agents (calls the T8 endpoint if present, otherwise returns a typed not-available error).
- [x] 2.5 Audit event per call (layer, tool, principal, outcome; no arguments with values); test a denied call is recorded.
- [x] 2.6 Verify: `cargo nextest run -p ls-control-plane mcp`.

## 3. Agent MCP [sonnet]
- [x] 3.1 `/mcp` route on the gateway with agent-token auth (audience `gateway`); tests for expired and wrong-audience tokens.
- [x] 3.2 Default-on tools: list my keys, relay an HTTP request (reuses the existing relay path and redaction), explain a block.
- [x] 3.3 [opus] `issue_short_lived_credential`: minutes-long, one job, destroyed after, off by default, audited; adversarial cases that the stored value never appears.
- [x] 3.4 Switch enforcement and audit event per call, as on the hub.
- [x] 3.5 Verify: `cargo nextest run -p ls-gateway mcp`.

## 4. Sign-in and clients [sonnet]
- [x] 4.1 Hub OAuth flow per the research note (protected-resource metadata, issuer config for Keycloak locally); an end-to-end test with a scripted MCP client that signs in and lists tools.
- [ ] 4.2 Client revoke bound to the OAuth `client_id` (hub) or the agent (gateway): a revoked client's next call is refused with `401`, and so is a fresh `initialize` after revoke; test both.
- [ ] 4.3 Verify: `just up && cargo nextest run -p ls-control-plane --test mcp_e2e`.

## 5. Console and desktop surface [sonnet]
- [x] 5.1 `apps/web` Tools page (one switch per tool, per layer) and Clients page (list, revoke), with Vitest tests including `403` and empty states.
- [ ] 5.2 `apps/desktop` Tools and Clients views on the same client methods, with Vitest tests.
- [ ] 5.3 Verify: `npm test --workspace apps/web --workspace apps/desktop && just apps-build`.

## 6. Adversarial [sonnet]
- [ ] 6.1 Add adversarial cases to `tests/`: a tool-list scan for value-like fields on both servers, a sentinel secret that must not appear in any MCP result, log or audit row, and an off-tool call by name.
- [ ] 6.2 Verify: `just adversarial-gate`.

## 7. Local verification [sonnet]
- [ ] 7.1 `just up`, the MCP end-to-end smoke test, `just apps-build`, then `just ci`.
- [ ] 7.2 Run the manual `ci-platforms` workflow if this is the last change of its phase and record the result in progress.md.
