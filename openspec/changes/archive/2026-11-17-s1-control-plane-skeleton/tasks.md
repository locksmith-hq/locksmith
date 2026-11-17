# Tasks: S1 control-plane skeleton

## 1. Service crate and health
- [x] 1.1 Create `services/control-plane` (package `ls-control-plane`, binary `locksmith-api`) and add `services/*` to the workspace members. Config from env vars per design decision 14; errors name the variable, never its value.
- [x] 1.2 axum app with tower-http layers (request id, 10 s timeout, 64 KiB body limit), `GET /healthz` and `GET /readyz` (503 until the DB is reachable and migrated).
- [x] 1.3 Dev org binding: `OrgBinding` extractor reading `X-Locksmith-Dev-Org` only with `LOCKSMITH_DEV_AUTH=1`; refuse to start with dev auth on a non-loopback bind; WARN log at startup when dev auth is on. Tests for both spec scenarios.
- [x] 1.4 Verify: `cargo nextest run -p ls-control-plane` passes and `cargo clippy -p ls-control-plane --all-targets -- -D warnings` is clean.

## 2. Schema and tenancy [opus]
- [x] 2.1 Migrations: `locksmith_owner` and `locksmith_app` roles (idempotent, dev passwords from `infra/compose/.env.example`), and tables `orgs`, `projects`, `environments`, `secrets` with UUIDv7 ids, `org_id`, composite FKs `(org_id, parent_id)`, unique names per parent, `FORCE ROW LEVEL SECURITY` and policies (design decision 6). No value column anywhere.
- [x] 2.2 Startup runs migrations through the owner pool, then closes it; the request path only uses the app pool. Test: the app role is not superuser, not `BYPASSRLS` and owns no table.
- [x] 2.3 Tenant transaction helper (design decision 5) as the only way handlers reach the DB, with a child tracing span per transaction. Move the A0 tenant lint so it also scans `services/`, and keep the `a0-spikes` lint test green.
- [x] 2.4 Testcontainers tests on `postgres:18`: cross-org read and list return nothing, a cross-org parent FK fails, and pooled-connection reuse with pool size 1 sees no org.
- [x] 2.5 Verify: `cargo nextest run -p ls-control-plane -p a0-spikes` passes.

## 3. Resource API
- [x] 3.1 Orgs (dev create, get) and projects (create, get, list, patch name and description, delete) under `/v1`, with `201` plus `Location`, `404` for other orgs' ids, and `409` on duplicate names.
- [x] 3.2 Environments under a project and secret metadata under a project and environment (create, get, list, patch, delete). `version_count` is always 0 in S1.
- [x] 3.3 RFC 9457 problem details (design decision 9) and `deny_unknown_fields` on every input type. A test checks that a `value` field gets `400` and stores nothing.
- [x] 3.4 Keyset pagination with an opaque `next` cursor and `limit` of at most 100. A test covers 120 items with `limit=50`.
- [x] 3.5 Verify: `cargo nextest run -p ls-control-plane` passes, covering every `control-plane-api` scenario except the e2e ones.

## 4. OpenAPI contract
- [x] 4.1 Annotate routes and schemas with utoipa and utoipa-axum, and serve `/openapi.json` (OpenAPI 3.1).
- [x] 4.2 Commit `services/control-plane/openapi.json`. Add a snapshot test that fails on drift and prints the difference, and that rewrites the file when `UPDATE_OPENAPI=1` is set. Sorted keys, deterministic output.
- [x] 4.3 Verify: `cargo nextest run -p ls-control-plane -E 'test(openapi)'` passes. After a deliberate route rename, the test fails; revert the rename.

## 5. Telemetry
- [x] 5.1 OTLP HTTP export of traces and logs (design decision 12) with `service.name=locksmith-api`. Server spans are named by route template and carry method, status and org id; no headers or bodies are recorded.
- [x] 5.2 Exporter failure never fails a request. A test with an unreachable OTLP endpoint checks that requests succeed, and that the export error is logged at most once a minute.
- [x] 5.3 Verify: with `just up` and `just api`, one request appears in Tempo through the `grafana` MCP or Grafana's datasource proxy. Record the query used in progress.md.

## 6. Recipes and end-to-end
- [x] 6.1 Add a `just api` recipe that runs `locksmith-api` against `just up`, with dev auth on and a loopback bind. Document it in `docs/dev-harness.md`, including the debug commands from design.md.
- [x] 6.2 Add `tests/e2e/tests/api.rs`, which drives the running service: project tree create and read, cross-org isolation, pagination, `/readyz`, and a trace for `POST /v1/projects` with a database child span found in Tempo (polled for up to 30 s).
- [x] 6.3 Leak check: use a canary as a secret description, run the e2e suite, then run `just leak-scan`. The canary may appear only in the database. Logs and traces must be clean.
- [x] 6.4 Verify: `just up && just api` (in the background), then `cargo nextest run -p ls-e2e --test api` and `just leak-scan` pass.

## 7. Local verification
- [x] 7.1 `just reset && just up && just harness-check`, then `just api` in the background, `cargo nextest run -p ls-e2e --test api`, `just leak-scan`, and `just ci`. Fill in the exact resolved versions in the design.md "OSS used" table.
