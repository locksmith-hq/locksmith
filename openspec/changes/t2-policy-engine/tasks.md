# Tasks: T2 policy engine

## 1. Contract [sonnet]
- [ ] 1.1 Add the policy request and response types, `POST /v1/policies/check`, the `policy-denied` problem slug and `GrantMode::{Delegate, Inject}` to the OpenAPI schema (utoipa); stubs return `501`; regenerate `packages/control-plane-client`.
- [ ] 1.2 Fixtures in `packages/control-plane-client` for every new route (two built-in policies, one org policy, an allow and a deny check result, a `422` validation error).
- [ ] 1.3 Verify: `cargo nextest run -p ls-control-plane openapi` and `npm test --workspace packages/control-plane-client`.

## 2. ls-policy crate [opus]
- [ ] 2.1 Create `crates/ls-policy` with `cedar-policy` pinned, the Cedar schema and `decide()` returning decision plus policy ids; record the version check in the design's OSS table.
- [ ] 2.2 Built-in `roles.cedar` and `guards.cedar` embedded with `include_str!`; a table test of every role x action, and the `inject` forbid for `Agent` that no added `permit` can undo.
- [ ] 2.3 Verify: `cargo nextest run -p ls-policy` and `cargo deny check`.

## 3. Storage and policy routes [sonnet]
- [ ] 3.1 Migration `org_policies` with forced RLS and version rows, widen the `agent_grants.mode` check; cover the table in `ls-tenant-lint`.
- [ ] 3.2 Policy list, create, replace and delete (owners only) with schema validation, `422` on failure and ledger events `policy.created|updated|deleted`.
- [ ] 3.3 Verify: `cargo nextest run -p ls-control-plane policies tenancy` and `cargo nextest run -p ls-tenant-lint`.

## 4. Enforcement in the control plane [opus]
- [ ] 4.1 An `authorize(action)` extractor that builds entities from the bound org and calls `ls-policy`; a deny is `403 policy-denied` and a `policy.denied` ledger event.
- [ ] 4.2 Map every mutating and secret-reading route to an action; a test walks the OpenAPI document and fails on any route without one.
- [ ] 4.3 Grant creation accepts `delegate` and `inject` and is authorized with the grant mode in context, so `inject` for an agent is refused.
- [ ] 4.4 `POST /v1/policies/check` (owners and admins) returning decision and policy ids without acting.
- [ ] 4.5 Verify: `cargo nextest run -p ls-control-plane policy grants` (member `403`, admin allowed, cross-org `404`, inject refused).

## 5. Agent use in the gateway [sonnet]
- [ ] 5.1 The internal grants endpoint evaluates `use.<mode>` per grant at request time and returns only allowed grants with their mode.
- [ ] 5.2 The gateway refuses delegated use without a `delegate` grant and relay without a `relay` grant; the audit record carries the deciding policy ids.
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
