# Proposal: S1 control-plane skeleton

## Why
Every later server change (S2 encryption, S3 gateway, S5 audit, T1–T4) needs a running service with a schema, an API contract and traces to build on. A0 fixed the hard-to-change data choices (`openspec/decisions.md` A0-1 to A0-6), and the owner approved them in #37. S1 turns those decisions into the first real service, so the next changes add behaviour instead of scaffolding.

## What Changes
- A new axum service, `services/control-plane` (binary `locksmith-api`), added to the Cargo workspace.
- Postgres 18 migrations run as an owner role. The service connects as an app role with no `BYPASSRLS`. Tenant tables use `org_id` plus `FORCE ROW LEVEL SECURITY`, and the org is set per transaction (A0-4, A0-5). IDs are UUIDv7 (A0-6).
- A versioned REST API under `/v1` for orgs, projects, environments and **secret metadata**: name, description, timestamps and version count. Values arrive in S2, and no value field exists anywhere in S1.
- An OpenAPI 3.1 document generated from the code, served at `/openapi.json` and committed as a snapshot, so a drift test catches unreviewed API changes.
- `/healthz` (liveness) and `/readyz` (database reachable, migrations applied).
- OpenTelemetry traces and logs over OTLP to the F0 Grafana stack, with one span per request and per database transaction.
- Dev-only org selection: with `LOCKSMITH_DEV_AUTH=1` and a loopback bind, the `X-Locksmith-Dev-Org` header picks the org. The service refuses to start with dev auth on any other bind. T1 replaces this with OIDC.
- `just api` runs the service against `just up`. An API e2e suite in `tests/e2e` drives it.

## Capabilities

### New Capabilities
- `control-plane-api`: the tenant-scoped REST resources (orgs, projects, environments, secret metadata), their isolation, errors, pagination and the OpenAPI contract.
- `service-operations`: how a Locksmith service starts, migrates, reports health and emits telemetry.

### Modified Capabilities
- (none) `data-foundations` requirements are applied, not changed.

## Out of scope
- Secret values, encryption and KMS (S2). Gateway and injection (S3). Agent identity and tokens (S4). Audit ledger (S5).
- Human sign-in, OIDC and RBAC (T1, T2). S1's dev header is not an auth system.
- Console UI (T3), the TypeScript client and SDK generation (P3), and AWS deployment (P1).
- Rate limiting and quotas.

## Depends on
A0 (archived; decisions A0-1 to A0-6 in `openspec/decisions.md`). F0 for the compose stack and F1 for `just leak-scan` and nextest.

## Impact
- New: `services/control-plane/` (crate, migrations, `openapi.json` snapshot) and `tests/e2e/tests/api.rs`.
- Changed: root `Cargo.toml` (`services/*` in workspace members), `justfile` (`api` recipe), `.mcp.json` only if a new read-only DB role is needed for the app schema.
- Dependencies: axum, tower-http, utoipa and utoipa-axum, opentelemetry and tracing-opentelemetry, plus sqlx-core and sqlx-postgres (as in `a0-spikes`).
