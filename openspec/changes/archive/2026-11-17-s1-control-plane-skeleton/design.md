# Design: S1 control-plane skeleton

## Context
- `services/` exists but is empty, and the Cargo workspace only includes `crates/*` and `tests/e2e`.
- `crates/a0-spikes` already proves the A0 tenancy pattern on Postgres 18:
  - an owner role and an app role (`migrations/0001_roles.sql`);
  - `FORCE ROW LEVEL SECURITY` with a per-transaction `set_config` (`src/tenant.rs`);
  - a lint that bans session-level `SET app.` (`src/tenant_lint.rs`).
- It uses `sqlx-core` and `sqlx-postgres` directly, because the `sqlx` facade pulls in `libsqlite3-sys`, which clashes with `ls-vault`'s `rusqlite` (see its `Cargo.toml`).
- F0's compose stack provides:
  - `postgres:18.7` on 5432;
  - `grafana/otel-lgtm` (Grafana on 3000, OTLP on 4317/4318, with Loki, Tempo and Prometheus);
  - OpenBao and WireMock.
- F1 provides nextest, testcontainers and `just leak-scan`.
- Binding decisions: `openspec/decisions.md` A0-1 to A0-6. See proposal.md for the motivation.

## Goals / Non-Goals
**Goals:** one service crate that every later server change extends without restructuring; tenancy enforced by the database, not by handler discipline; an API contract that cannot drift silently; traces an agent can query.

**Non-Goals:** production deployment shape (P1), horizontal-scaling concerns beyond a stateless process, API stability guarantees (the API is `v1` but pre-alpha until P3).

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **Crate `services/control-plane`** (package `ls-control-plane`, binary `locksmith-api`), with `services/*` added to the workspace members. | Putting it in `crates/` (AGENTS.md layout puts axum backends in `services/`) | `AGENTS.md` layout table; `services/README.md` |
| 2 | **axum 0.8 with tower-http** for tracing, request id, timeout and body limit. | actix-web (a separate runtime and middleware model from the tokio and tower stack the repo already uses); poem (smaller community) | crates.io: axum 0.8.9 (2026-04-14, about 167M recent downloads); tower-http 0.7.1 (2026-08-31) |
| 3 | **sqlx-core and sqlx-postgres 0.9, runtime-checked queries** (`query_as` plus `FromRow`), no compile-time macros. | The `sqlx` facade (sqlite link conflict, as in `a0-spikes`); compile-time `query!` (needs the facade's macros plus `DATABASE_URL` or offline data); diesel (sync core, heavier for RLS `set_config`) | `crates/a0-spikes/Cargo.toml` comment; sqlx-postgres 0.9.0 (2026-05-21) |
| 4 | **Two roles, two pools.** `locksmith_owner` runs migrations at startup, then its pool is closed. `locksmith_app` (`NOSUPERUSER NOBYPASSRLS`, owns nothing) serves requests. Dev passwords live in `infra/compose/.env.example`, like the existing compose credentials. | One role with `BYPASSRLS` off (the owner still bypasses RLS on its own tables); a separate migrate job (needed for ECS in P1, not locally) | A0-4; `a0-spikes/migrations/0001_roles.sql`; Postgres docs, "Row Security Policies" (table owners bypass RLS unless FORCE) |
| 5 | **One way into the database: a tenant transaction helper.** It runs `BEGIN`, then `set_config('app.org_id', $1, true)`, then the work, then `COMMIT`, inside one tracing span. Handlers never get a raw pool. The A0 lint moves into a shared place and also scans `services/`. | Setting the org per connection (leaks across the pool: A0's pooled-reuse spike) | A0-5; the `a0-spikes` `rls` test "pooled-connection reuse" |
| 6 | **Schema.** `orgs` has an RLS policy `id = current_setting('app.org_id')::uuid`. `projects`, `environments` and `secrets` carry `org_id` and use **composite foreign keys** `(org_id, parent_id)`, so a child can never point at another org's parent. A `secret_versions` table is **not** created yet: S2 owns it, and `version_count` is 0 until then. | Org id only on the top table, with joins for isolation (one forgotten join leaks data) | A0-4; Postgres docs, "Row Security Policies" |
| 7 | **Org creation in dev:** the app generates a UUIDv7, sets it as the org context, and inserts the row with that id, so even org creation passes through RLS. | An owner-role admin path (would put the owner pool on the request path) | A0-6 (app-generated v7 is allowed) |
| 8 | **OpenAPI from code with utoipa 6 and utoipa-axum.** Routes and schemas are declared once. `/openapi.json` is served, `services/control-plane/openapi.json` is committed, and a test fails on drift (`UPDATE_OPENAPI=1` rewrites it). | aide (about 1.5M recent downloads against utoipa's 23M); a hand-written spec (drifts) | crates.io: utoipa 6.0.0 and utoipa-axum 0.3.0 (2026-09-22) |
| 9 | **RFC 9457 problem details** through a small in-house type (`src/problem.rs`), with a stable `type` URI per error kind (`urn:locksmith:problem:<validation\|unauthenticated\|not-found\|conflict\|payload-too-large\|unsupported-media-type\|unavailable\|internal>`). `http-api-problem` 0.60.0 was checked and rejected: it targets RFC 7807 and its axum integration goes through `axum-core`, for a type this small. Serde error text can quote request values, so only an unknown or missing field name is ever echoed. | Plain-text errors | RFC 9457 |
| 10 | **Keyset pagination on the UUIDv7 id.** The cursor is the base64url of the last id, with `limit` at most 100. | Offset pagination (unstable under inserts, slow on large offsets) | UUIDv7 is time-ordered (A0-6 spike) |
| 11 | **Strict request bodies:** `#[serde(deny_unknown_fields)]` on every input type, so a stray `value` field is a `400`, not a silent drop. | Ignoring unknown fields (a client might believe it stored a secret) | Spec, "Secret metadata never carries a value" |
| 12 | **Telemetry:** `tracing`, `tracing-opentelemetry` and `opentelemetry-otlp` over HTTP/protobuf to `:4318`, with resource `service.name=locksmith-api`. tower-http's `TraceLayer` names server spans from `MatchedPath` and records no headers or bodies. Logs go out through `opentelemetry-appender-tracing`. The batch exporter drops on failure and does not block requests. | `axum-tracing-opentelemetry` (an extra dependency for one layer we configure ourselves) | opentelemetry and opentelemetry-otlp 0.33.1 (2026-10-09); tracing-opentelemetry 0.34.0 (2026-09-23); `docs/dev-harness.md` (OTLP on 4318) |
| 13 | **Dev org binding:** the `X-Locksmith-Dev-Org` header is accepted only with `LOCKSMITH_DEV_AUTH=1`. At startup, the service exits if dev auth is on and any bind address is not loopback. Behind one `OrgBinding` extractor that T1 replaces with JWT verification. | A static dev bearer token (still an auth system to remove later, and no safer on loopback) | Spec, "Dev-only org binding"; A0-15 (T1 uses generic OIDC) |
| 14 | **Config from environment variables only:** `DATABASE_URL`, `DATABASE_OWNER_URL`, `LOCKSMITH_BIND`, `OTEL_EXPORTER_OTLP_ENDPOINT` and `LOCKSMITH_DEV_AUTH`. Error messages name the variable, never its value. | A config file (another format to secure and ship) | 12-factor; AGENTS.md rule on never printing secrets (DSNs hold passwords) |
| 15 | **Parent deletes are RESTRICT, surfaced as `409`.** Deleting a project that still has environments, or an environment that still has secrets, fails with `409 Conflict` (`urn:locksmith:problem:conflict`); clients delete children first. Child inserts check their parent in the same transaction and return `404` when it is missing or belongs to another org. Orgs are never deleted in S1. | `ON DELETE CASCADE` (one call silently destroys a whole secret tree, wrong default for a secrets product); `422` or `400` for non-empty parents (the request is well formed, the state conflicts) | RFC 9110 section 15.5.10 (`409`); migration `0002_tenancy_schema.sql` (no cascade on any FK) |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| axum | MIT | 0.8.9 | 2026-04-14 | HTTP framework | not AGPL |
| tower-http | MIT | 0.7.1 (0.6.11 also resolves, via another crate) | 2026-08-31 | trace, request-id, timeout and limit layers | not AGPL |
| sqlx-core, sqlx-postgres | MIT/Apache-2.0 | 0.9.0 | 2026-05-21 | Postgres driver and migrations (already used) | not AGPL |
| utoipa, utoipa-axum | MIT/Apache-2.0 | 6.0.0 / 0.3.0 | 2026-09-22 | OpenAPI from code | not AGPL |
| tracing-subscriber | MIT | 0.3.23 | 2026-03-13 | subscriber | not AGPL |
| opentelemetry, opentelemetry_sdk, opentelemetry-otlp | Apache-2.0 | 0.33.1 | 2026-10-09 | OTLP export | not AGPL |
| tracing-opentelemetry | MIT | 0.34.0 | 2026-09-23 | tracing to OTel bridge | not AGPL |
| uuid (`v7`) | MIT/Apache-2.0 | 1.29.2 | n/a | app-side v7 ids | not AGPL |
| testcontainers | MIT/Apache-2.0 | 0.28.0 | n/a | crate integration tests on `postgres:18` (`GenericImage`; the postgres module needs testcontainers 0.27, so it is not used) | not AGPL |
| tracing-log | MIT | 0.2.0 | n/a | normalise `log`-bridged events so exporter diagnostics are redacted | not AGPL |
| similar (dev) | Apache-2.0 | 3.2.1 | n/a | readable diff in the OpenAPI snapshot test | not AGPL |

Versions are the resolved ones from `Cargo.lock`.

## Built in-house
- The tenant transaction helper and `OrgBinding` extractor (about 100 lines). No crate does RLS `set_config` per transaction with sqlx 0.9. Searched crates.io for "sqlx rls" and "postgres row level security axum": nothing maintained.
- The problem-details type, unless `http-api-problem` qualifies (decision 9).

## Risks / Trade-offs
- [A handler bypasses the helper with a raw pool] → the app pool is private to the helper module, and the lint fails on `set_config(..., false)` and `SET app.` anywhere in `services/`.
- [Running migrations at startup races when several replicas start] → sqlx's migrator takes a Postgres advisory lock, and P1 moves migrations to a one-shot task.
- [The dev header ships to a real deployment] → the loopback check at startup, plus a startup log line at `WARN` whenever dev auth is on. T1 deletes the extractor variant.
- [OpenAPI snapshot churn] → only generated output is committed, and `UPDATE_OPENAPI=1` regenerates it deterministically (sorted keys).
- [A Grafana trace query is flaky right after a request] → the e2e test polls Tempo through Grafana's datasource proxy for up to 60 s (Tempo takes about 30 s to index a trace).

## Migration Plan
New service, nothing to migrate. Rollback means reverting the merge commit. The roles and schema live only in the dev database, and `just reset` clears them.

## How an agent debugs this
- **Logs and traces:** the `grafana` MCP (Loki `{service_name="locksmith-api"}`, Tempo search for service `locksmith-api`), or `just logs` for compose services.
- **Database:**
  - The `postgres` MCP: `\dp`, `SELECT * FROM pg_policies`, `SELECT rolname, rolbypassrls FROM pg_roles WHERE rolname LIKE 'locksmith_%'`.
  - `just psql -c "SET ROLE locksmith_app; SELECT set_config('app.org_id','<uuid>',true); SELECT * FROM projects"` reproduces what a request sees.
- **API:** `curl -H 'X-Locksmith-Dev-Org: <uuid>' localhost:8080/v1/projects` against `just api`; `/openapi.json` for the contract.
- **Tests:**
  - `cargo nextest run -p ls-control-plane` (testcontainers);
  - `cargo nextest run -p ls-e2e --test api` (needs `just up` and `just api`).
