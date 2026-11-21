# Tasks: P4 SDKs and remote MCP setup

## 1. SDK package [sonnet]
- [x] 1.1 [haiku] Re-check `openapi-fetch` (latest version, licence, release date) and record it in design.md "OSS used"; pin it exactly.
- [x] 1.2 Create `packages/sdk` (`@locksmith/sdk`, Apache-2.0, npm workspace): `npm run gen` writes `src/schema.d.ts` from `services/control-plane/openapi.json`; `createLocksmith({ baseUrl, token })` returns an `openapi-fetch` client with bearer auth.
- [x] 1.3 Typed `LocksmithError` (status plus RFC 9457 problem fields) and a cursor-paging helper; Vitest tests for a 403 problem, a network error and two pages, with no console output.
- [x] 1.4 Drift test: regenerate to a temp dir and diff against `src/schema.d.ts`; operation-coverage test: every `operationId` in the spec has a typed path; no-value-route test using the console leak-check denylist.
- [x] 1.5 Verify: `npm test --workspace packages/sdk`.

## 2. One client [sonnet]
- [ ] 2.1 `packages/control-plane-client` re-exports types from `@locksmith/sdk` and implements its `Client` through the SDK; delete its hand-written `fetch` code and its own `schema.d.ts` and `gen:types` script.
- [ ] 2.2 Keep the enrollment-secret rule: a test asserts the secret only lives in the returned object (not logged, cached or stored).
- [ ] 2.3 Verify: `npm test --workspace packages/control-plane-client && npm test --workspace apps/web && npm test --workspace apps/desktop && just apps-build`.

## 3. Recipes and smoke [sonnet]
- [ ] 3.1 `just sdk-gen` (regenerate) and `just test sdk`; add the `packages/sdk` row to `docs/testing.md`, which tree-check requires.
- [ ] 3.2 `just sdk-smoke` plus a script under `tests/e2e`: against `just up`, sign in as the Keycloak test user, then create, list and delete an agent through the SDK, and run `just leak-scan` on its output.
- [ ] 3.3 `packages/sdk/README.md`: install from the workspace, auth, errors, paging, and one CI example (create a grant).
- [ ] 3.4 Verify: `just up && just sdk-smoke && just test sdk && just tree-check`.

## 4. Remote Hub MCP setup [sonnet]
- [ ] 4.1 [haiku] For each agent in `agents.rs`, record with a source URL whether it supports a remote Streamable HTTP MCP server with OAuth, and its config shape, in `docs/research/remote-mcp-auth.md` (append a section; mark "not verified" when no source is reachable).
- [ ] 4.2 `agents.rs`: an optional remote-MCP entry per supported agent (URL `<hub>/mcp` and the public client id only); regenerate `integrations/*` with `UPDATE_INTEGRATIONS=1`; the drift test passes.
- [ ] 4.3 `smith init --hub <url>` writes the entries idempotently (`--dry-run` prints them), and `smith doctor` adds `hub.mcp` (ok / missing / unsupported per agent); tests include a second-run no-op and a scan for no token, client secret or canary in the written files.
- [ ] 4.4 `integrations/generic-mcp/README.md` (create it if P3 has not yet): remote Hub MCP URL, discovery via `WWW-Authenticate`, and the pre-registered public client for any other MCP client.
- [ ] 4.5 Verify: `cargo nextest run -p smith-cli init doctor agents && just test smith-cli`.

## 5. Local verification [sonnet]
- [ ] 5.1 `just up`, `just sdk-smoke`, `just apps-build`, then `just ci`.
- [ ] 5.2 Run the manual `ci-platforms` workflow if this is the last change of its phase and record the result in progress.md.
