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
