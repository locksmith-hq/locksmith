# Tasks: T2 policy engine

## 1. Contract [sonnet]
- [ ] 1.1 Add the policy request and response types, `GET/POST/PUT/DELETE /v1/policies`, `POST /v1/policies/check`, the `policy-denied` problem slug and `GrantMode` values `delegate` and `inject` to `services/control-plane/openapi.json` as zod schemas in `apps/api/src/domains/policy/policy.schemas.ts`; mark the new paths `nest` in `apps/api/route-table.json`; NestJS stubs return `501`; regenerate `packages/control-plane-client`.
- [ ] 1.2 Fixtures in `packages/control-plane-client` for every new route (two built-in policies, one org policy, an allow and a deny check result, a `422` validation error).
- [ ] 1.3 Verify: the b1 OpenAPI drift check (`npx turbo run test --filter=@locksmith/api`) and `npm test --workspace packages/control-plane-client`.

## 2. Policy module [opus]
- [ ] 2.1 `apps/api/src/platform/policy`: `@cedar-policy/cedar-wasm` pinned exactly, the Cedar schema, and a `PolicyService.decide()` returning decision plus policy ids; record the version check in the design's OSS table.
- [ ] 2.2 Built-in `roles.cedar` and `guards.cedar` shipped as package assets; a vitest table test of every role x action, and the `inject` forbid for `Agent` that no added `permit` can undo.
- [ ] 2.3 Verify: `npx turbo run test typecheck --filter=@locksmith/api -- policy` and `npm audit --workspace apps/api --omit=dev`.

## 3. Storage and policy routes [sonnet]
- [ ] 3.1 Migration `org_policies` (in the Rust `migrate` binary's migrations, which own the schema per b1 task 2.3) with forced RLS and version rows, and the `agent_grants.mode` check widened; cover the table in `ls-tenant-lint`; regenerate Kysely types with `just api-types`.
- [ ] 3.2 Policy list, create, replace and delete (owners only) in `apps/api/src/domains/policy`, with Cedar validation, `422` on failure and ledger events `policy.created|updated|deleted` appended through the core client.
- [ ] 3.3 Verify: `npx turbo run test --filter=@locksmith/api -- policy tenancy`, `cargo nextest run -p ls-tenant-lint` and `just api-contract` for the policy paths.

## 4. Enforcement in the API [opus]
- [ ] 4.1 `@Authorize(action)` decorator and `PolicyGuard` (on top of b1's auth and permission guards) that build entities from the request's org and call `PolicyService`; a deny is `403 policy-denied` and a `policy.denied` ledger event.
- [ ] 4.2 Map every mutating and secret-reading NestJS route to an action; a test walks the generated OpenAPI document and fails on any `nest` route without one.
- [ ] 4.3 Grant creation accepts `delegate` and `inject` and is authorized with the grant mode in context, so `inject` for an agent is refused.
- [ ] 4.4 `POST /v1/policies/check` (owners and admins) returning decision and policy ids without acting.
- [ ] 4.5 Verify: `npx turbo run test --filter=@locksmith/api -- policy grants` (member `403`, admin allowed, cross-org `404`, inject refused).

## 5. Agent use in the gateway [sonnet]
- [ ] 5.1 The API's internal grants endpoint evaluates `use.<mode>` per grant at request time and returns only allowed grants with their mode and deciding policy ids.
- [ ] 5.2 The Rust gateway refuses delegated use without a `delegate` grant and relay without a `relay` grant; the audit record carries the deciding policy ids.
- [ ] 5.3 Add adversarial cases to `tests/adversarial/`: agent asks for inject, relay-only grant used for delegate, an org policy forbidding `production`.
- [ ] 5.4 Verify: `cargo nextest run -p ls-gateway grants`, `bash tests/adversarial/run.sh`, `just leak-scan`.

## 6. Web console [sonnet]
- [ ] 6.1 Policies page: built-in policies read-only, org policies with a textarea editor for owners, server validation errors shown inline.
- [ ] 6.2 Check-access form and a mode picker on the grant form (`relay`, `delegate` only for agents).
- [ ] 6.3 Verify: `npm test --workspace apps/web` (fixtures cover `403`, `422`, allow and deny).

## 7. Desktop surface [sonnet]
- [ ] 7.1 Desktop Policies view and grant mode picker in `apps/desktop/src` on the shared client; Vitest tests including `403` and `422`.
- [ ] 7.2 Verify: `npm test --workspace apps/desktop` and `just apps-build`.

## 8. Local verification [sonnet]
- [ ] 8.1 `just policy-smoke` and `tests/e2e/tests/policy.rs`: owner adds a `production` forbid, the agent relay is refused, a member's grant create is `403`, an inject grant for an agent is refused, check-access explains each.
- [ ] 8.2 `just up`, `just policy-smoke`, `just apps-build`, then `just quick`.
