# Tasks: B4 API contract suite

## 1. Runner and coverage [sonnet]
- [ ] 1.1 `tests/api-contract` npm workspace (private, ESM, vitest, AGPL-3.0-only; add it to the root `workspaces`), base URL from `API_CONTRACT_URL`, a seeding helper that creates two users in two orgs through dev auth (as `just api` enables), and the normaliser (ids, timestamps, tokens to placeholders in order of first appearance) with unit tests; `scripts/tree-check.sh` and `docs/testing.md` entries.
- [ ] 1.2 `scripts/api-contract.sh <base-url>` runs the suite and writes the normalised transcript under `target/api-contract/`; `--diff <url-a> <url-b>` runs both and prints the first differing status, header or body field per path, exiting non-zero on any difference; `just api-contract`; `scripts/api-contract.test.sh` covers the diff on two planted transcripts.
- [ ] 1.3 Coverage test: reads `services/control-plane/openapi.json` and fails, naming the path, when a path and method has no scenario and is not in an exclusion list with a reason.
- [ ] 1.4 Verify: `npm test --workspace tests/api-contract -- normalise coverage` and `bash scripts/api-contract.test.sh`.

## 2. Scenarios: tenancy and secrets [sonnet]
- [ ] 2.1 Scenarios for `/v1/auth/sign-in`, `/v1/auth/sign-out`, `/v1/orgs`, `/v1/orgs/current`, `/v1/orgs/{org_id}`, `/healthz`, `/readyz` and `/.well-known/jwks.json`: success, validation error, missing-token 401, cross-tenant 404 or 403 where the path is tenant-scoped.
- [ ] 2.2 Scenarios for projects and environments (all methods).
- [ ] 2.3 Scenarios for secrets and versions (metadata and ciphertext only, canary values from `just canary`).
- [ ] 2.4 Verify: `just up`, `just api`, then `just api-contract http://127.0.0.1:8080` passes for these files.

## 3. Scenarios: agents, workloads, MCP and audit [sonnet]
- [ ] 3.1 Scenarios for agents, enrollment secrets, grants and `/v1/agent-tokens`.
- [ ] 3.2 Scenarios for workload identities, `/v1/workload-tokens` and `/v1/bindings`.
- [ ] 3.3 Scenarios for `/v1/mcp/clients`, client revoke, `/v1/mcp/tools`, `/v1/audit/events` and `/v1/audit/status`.
- [ ] 3.4 Scenarios for every `/internal/v1/*` path with the gateway's internal credential and without it (401).
- [ ] 3.5 Verify: `just api-contract http://127.0.0.1:8080` passes with the coverage test reporting no missing path.

## 4. Local verification
- [ ] 4.1 `just up`, `just api`, `just api-contract http://127.0.0.1:8080` twice with identical transcripts, `just leak-scan`, `just apps-build`, then `just quick`; append to `openspec/changes/b1-nestjs-api/progress.md` that B1 tasks 1.4 to 1.6 can be verified.
