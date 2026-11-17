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

## 2026-11-17 worker
- Task: 4.1-4.3 - done (sonnet impl + sonnet eval PASS); ci-fix: rust-lint failed on RUSTSEC-2026-0440 (astral-tokio-tar unmaintained, dev-only via testcontainers) -> ignore with justification in deny.toml
- Verified: cargo nextest run -p ls-control-plane -> 33 pass; clippy -D warnings, fmt clean; rename experiment makes the openapi snapshot test fail
- Notes for next session: start at 5.1 (OTLP telemetry). utoipa 6.0.0, utoipa-axum 0.3.0, similar 3.2.1 (dev) added; record in design.md OSS table in 7.1. openapi.json info.license is the placeholder "see repository". Dev auth header scheme `dev_org` is in the spec. cargo-deny is not installed in the VM, so advisories for new crates were not checked locally; watch rust-lint on this push.

## 2026-11-17 worker
- Task: 5.1-5.2 - failed (sonnet impl -> evaluator FAIL; opus fix -> opus evaluator FAIL); WIP committed, tasks NOT ticked; needs-rescue opened
- Verified: cargo nextest run -p ls-control-plane -> 38 pass; clippy -D warnings and fmt clean
- Notes for next session: OTLP telemetry is implemented (src/telemetry.rs, tests/telemetry.rs, tests/telemetry_export.rs). Remaining evaluator finding: `is_internal` in telemetry.rs matches `opentelemetry`/`opentelemetry_*` only, but OTel `otel_*!` macros use the hyphenated crate name as target (`opentelemetry-otlp`, `opentelemetry-http`, `opentelemetry-appender-tracing`). Those events bypass RedactInternal, the 60s limiter and the not_internal filter: at debug level the endpoint (userinfo/token) can print; PartialSuccess warns print unlimited. Fix: match any target starting with `opentelemetry` (also normalise `-`/`_`), add unit asserts for those targets and a test at a debug EnvFilter. Optional: redact otlp_endpoint in Config Debug. Then re-evaluate, tick 5.1/5.2, continue at 5.3.
