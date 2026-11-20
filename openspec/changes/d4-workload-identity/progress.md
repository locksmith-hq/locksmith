# Progress: d4-workload-identity

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-20 planner
- Task: none - planning
- Verified: `openspec validate d4-workload-identity --strict` -> valid, `bash scripts/tree-check.sh`
- Notes for next session: `x-depends_on` is empty because t1-human-auth is archived on main; no Contract group (no roadmap row needs D4). Reuse `auth/jwks.rs` `JwksCache` per stored issuer and the existing `AgentTokenSigner::mint`; resolve the `[verify]` item (jti cache crate) at task 4.1.

## 2026-11-20 worker (C)
- Task: 1.1, 1.2 - done (migration 0012 registered in `migrate.rs`, tenancy test updated; `workload.rs` validation, matcher, `lsw_` handle with 11 unit tests)
- Verified: `cargo nextest run -p ls-control-plane workload` 11 passed; `--test tenancy` 9 passed; `just ci` -> exit 0
- Notes for next session: 1.3 handlers (POST/GET/DELETE /v1/workload-identities, audit codes) and 1.4 api-types next. New migrations must also be listed in `src/migrate.rs` and the tenancy test (version list, table list, policy count).

## 2026-11-20 worker (C), second run
- Task: 1.3, 1.4, 1.5 - done (`api/workload_identities.rs`: POST/GET list/GET/DELETE under human auth and `with_org`; `workload_identity.created`/`.deleted` audit events; OpenAPI and `control-plane-client` types regenerated; `tests/workload_identities.rs`)
- Verified: `cargo nextest run -p ls-control-plane -p ls-audit workload tenant_lint openapi audit` 19 passed; `just ci` exit 0
- Notes for next session: validation errors are `400` (the repo's `Kind::Validation`), not `422` as task 1.5 text says; unpinned and bare-`*` policies are refused. Audit target type is `workload` (the ledger CHECK allows `[a-z]+` only, no underscore). Response field is `pattern`, not `value` (the OpenAPI guard bans response fields named `value`). Next: 2.1 per-issuer JwksCache registry.
