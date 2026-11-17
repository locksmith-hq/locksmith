# Progress: s1-control-plane-skeleton

Append-only session log for this change. Each scheduled or human session adds one entry at the end
before its final commit, and every session reads the last entries plus `git log` before starting.
Format:

## <UTC date time> <worker|review|human>
- Task: <id> - <done|failed|blocked|ci-fix>
- Verified: <command> -> <result>
- Notes for next session: <what to know, what to try next, traps found>

## 2026-11-17 human (owner session)
- Task: proposal - done (proposal, specs, design, tasks written)
- Verified: openspec validate s1-control-plane-skeleton -> see PR
- Notes for next session: start at 1.1. Reuse a0-spikes patterns (roles migration, tenant helper, lint) and its sqlx-core/sqlx-postgres split; do not add the sqlx facade.

## 2026-11-17 worker
- Task: 1.1-1.4, 2.1-2.5 - done (sonnet impl + sonnet eval for 1.x; opus impl + opus eval for 2.x)
- Verified: cargo nextest run -p ls-control-plane -p a0-spikes -p ls-tenant-lint -> 55 pass (a0-spikes rls needs postgres on 5432); clippy -D warnings and fmt clean
- Notes for next session: start at 3.1. testcontainers-modules 0.15 needs testcontainers 0.27 vs workspace 0.28, so tests use GenericImage("postgres","18"); update design.md OSS table in 7.1 and drop the unused workspace dep if nothing else uses it. First migration run needs a superuser (creates roles); later runs can use locksmith_owner. Parent deletes are RESTRICT: decide 409 vs cascade in 3.x. with_org closures must own captured data. Reviewer notes: a closure could still call set_config(...,true) with another org (lint does not catch), review section 3 handlers for it. .env.example LOCKSMITH_*_PASSWORD vars are unused (passwords hardcoded in 0001).

## 2026-11-17 worker
- Task: 3.1-3.5 - done (sonnet impl + sonnet eval PASS)
- Verified: cargo nextest run -p ls-control-plane -> 30 pass; clippy -D warnings, fmt, just ci -> green
- Notes for next session: start at 4.1 (utoipa OpenAPI). Routes live in src/api/*; RFC 9457 type is in-house (src/problem.rs, design decision 9); restrict-delete -> 409 (decision 15); pagination uses `cursor` param and `{items,next}`. Test Pg setup is duplicated between tests/tenancy.rs and tests/api.rs; could move to tests/common. Org PATCH/DELETE not implemented (not in task 3.1).
