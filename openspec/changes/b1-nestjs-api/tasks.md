# Tasks: B1 NestJS API

## 1. Contract and spikes [sonnet]
- [x] 1.1 Spike: a throwaway Nest 12 app (controller, decorator metadata injection, zod pipe, vitest test) compiled with TypeScript 7.0.2, then with 6.x; record in `docs/research/nestjs-typescript7.md` which build works, build time and any flag needed (source URLs and dates).
- [x] 1.2 [haiku] Spike: run oxlint, oxfmt and knip over `apps/web`, `apps/desktop`, `packages/*`; record findings and the config each needs in the same note.
- [ ] 1.3 Contract: freeze `services/control-plane/openapi.json` as the API contract (already protected by the oasdiff check) and list every path with its owner (`rust` or `nest`) in `apps/api/route-table.json`, all `rust`.
- [ ] 1.4 Contract: a scenario suite `tests/api-contract` (vitest and `fetch`, no framework coupling) with one data-driven scenario file per resource: for every path in `openapi.json` a success case, a validation error, a missing-token 401, and a cross-tenant 404 or 403; ids, timestamps and tokens are normalised in the recorded transcript. (Replaces "record the Rust integration tests": they call the router in-process with `tower::oneshot` from about 17 separate helpers, so there is no single place to record without editing every test file or adding recording code to the production router.)
- [ ] 1.5 Contract: `scripts/api-contract.sh <base-url>` runs the suite against any server and writes the normalised transcript; `scripts/api-contract.sh --diff <url-a> <url-b>` runs both and reports the first differing status, header or body field per path; `just api-contract`.
- [ ] 1.6 Verify: `just api-contract http://127.0.0.1:<rust-port>` passes against the Rust control plane from `just up`, and a second run produces the identical normalised transcript (the suite is deterministic).

## 2. Skeleton `apps/api` [sonnet]
- [ ] 2.1 `scripts/tree-check.sh` and `docs/testing.md` learn `apps/api`; `apps/api/package.json` (private, ESM, AGPL-3.0-only), `tsconfig` extending a shared base, Turborepo tasks `build`, `test`, `typecheck`.
- [ ] 2.2 Nest bootstrap: `ConfigModule` with a zod-validated env schema (fails fast, no defaults for secrets), `nestjs-pino` with redaction of `authorization` and any `*secret*`/`*token*` field, `GET /healthz` and `/readyz` with terminus.
- [ ] 2.3 Data layer: Kysely over `pg`, `kysely-codegen` from the migrated database into `src/db/types.ts`, a `just api-types` recipe and a CI drift check; migrations stay owned by the Rust `migrate` binary (record the decision in design.md).
- [ ] 2.4 Tenant interceptor: request-scoped transaction runner (nestjs-cls) that runs `set_config('app.org_id', $1, true)` first; a lint or test rule that bans session-level `SET` (decision A0-5).
- [ ] 2.5 Isolation tests: testcontainers Postgres, the app role (not owner, not `BYPASSRLS`), two orgs, cross-tenant read returns nothing, pooled-connection leakage test.
- [ ] 2.6 Jobs: pg-boss wired to the same Postgres; one example recurring job and its test; no Redis anywhere.
- [ ] 2.7 OpenAPI: generate the document from the zod schemas and fail CI if it differs from the frozen `openapi.json` for any path marked `nest`.
- [ ] 2.8 Verify: `npx turbo run build test typecheck --filter=@locksmith/api` and `just api-types`.

## 3. Tooling for all TypeScript [haiku]
- [ ] 3.1 Root `oxlint` config, applied through a `lint` Turborepo task per package; remove the ESLint config package only when every package passes (list leftovers).
- [ ] 3.2 Root `oxfmt` config with a pinned exact version and a `format:check` task; one formatting-only commit, listed in `.git-blame-ignore-revs`.
- [ ] 3.3 `knip.json` (workspaces, entry files per app, ignores with a reason each); a `knip` task; fix or justify every finding.
- [ ] 3.4 CI: the web job runs `turbo run lint format:check knip typecheck test`; a task-edit-guard note that workflow edits go on a harness-release branch.
- [ ] 3.5 Verify: `npx turbo run lint format:check knip typecheck --filter=...[origin/main]` is green.

## 4. Auth and request pipeline [sonnet]
- [ ] 4.1 Auth guard with `jose`: issuers, audiences and claim mapping read from config exactly as the Rust `auth/issuers` and `auth/jwt` modules do; unit tests with recorded Cognito and Keycloak tokens.
- [ ] 4.2 `/v1/auth/sign-in` and `/v1/auth/sign-out` on the NestJS side with the recorded behaviour (user and personal-org creation on first sign-in, audit event).
- [ ] 4.3 Permission guard and decorator reading the principal's role; a table-driven test of the role matrix copied from the Rust tests.
- [ ] 4.4 Error filter producing the same problem-details body as `problem.rs`; contract tests for 400, 401, 403, 404, 409, 422.
- [ ] 4.5 Verify: `just api-contract http://127.0.0.1:<nest-port>` for the auth and error recordings.

## 5. Gate: the Rust core boundary
- [x] 5.1 Gate: the owner confirms what stays in Rust behind the internal core API. Default: audit append and checkpoint signing, agent and workload token mint and verify, DEK wrap and unwrap through KMS. Alternatives: also keep authorization decisions in Rust (policy engine, T2), or keep only the gateway and crypto crates.
- [ ] 5.2 Core API contract: `services/core/openapi.json` (internal only) for the operations chosen at the gate, in the Rust workspace; a generated TypeScript client in `packages/core-client`.
- [ ] 5.3 Rust binary `ls-core` implementing it on top of the existing crates (`ls-audit`, `ls-envelope`, KMS code moved out of the control plane, no behaviour change); contract tests.
- [ ] 5.4 NestJS audit interceptor and token services call the core client; a failing core fails the request closed (never silently skip an audit append).
- [ ] 5.5 Verify: leak scan with canaries (`just leak-scan`) after the API and core suites; `cargo nextest run -p ls-core`.

## 6. Gate: existing endpoints
- [x] 6.1 Gate: the owner decides whether the existing Rust endpoints are ported (strangler, module by module) or only new endpoints go to NestJS, and how the in-flight changes t6, t7 and t8 land (finish in Rust first, or port after).
- [ ] 6.2 Port `orgs` and `memberships` (module, controller, service, store, in-memory tests); flip its paths in the route table only when `just api-contract` passes.
- [ ] 6.3 Port `projects` and `environments` likewise.
- [ ] 6.4 Port `users` and `agents` likewise (agent token issuance calls the core).
- [ ] 6.5 Port `workload-identities` and `workload-tokens`, then `audit` reads, then `secrets` and `versions` metadata (ciphertext only).
- [ ] 6.6 Each port: delete nothing from Rust until the path has run on NestJS in dev for a week; then remove the Rust handler in its own PR.
- [ ] 6.7 Verify per port: contract runner, cross-tenant tests against both servers, `npx turbo run test --filter=@locksmith/api`.

## 7. Routing and deploy [sonnet]
- [ ] 7.1 Local: the compose proxy reads `route-table.json` and sends each path to the Rust or Node container; `just up` starts both.
- [ ] 7.2 Dev (private repo task, recorded here): CloudFront origins and behaviours generated from the same table; owner applies.
- [ ] 7.3 Web console keeps one API base; no change needed beyond the proxy.
- [ ] 7.4 Verify: `just up && just api-contract http://127.0.0.1:<proxy-port>`.

## 8. Protected files (harness-release branch, owner approval)
- [ ] 8.1 Update `openspec/config.yaml` context: stack (NestJS API, Rust for secrets, keys, proxies, gateway), licence line (AGPL for server components including `apps/api`, `ee/` exists), tooling (oxlint, oxfmt, knip, Turborepo).
- [ ] 8.2 Update `AGENTS.md` build and layout sections and the security rules' wording ("Use Rust for anything that touches secrets" stays; the API is no longer in it).
- [ ] 8.3 `CODEOWNERS` entries for `apps/api` crypto-adjacent files (`src/platform/auth`, the core client).

## 9. Local verification
- [ ] 9.1 `just up`, the change's smoke test (`just api-contract` against the proxy with all migrated paths on `nest`), `just apps-build`, then `just quick`.
