# Proposal: B1 NestJS API (the control plane, built the way Infisical builds its backend)

## Why

Owner decision OC-8 (2026-11-22): the backend API moves to NestJS 12 on TypeScript, following Infisical's backend, while everything that touches plaintext secrets, keys or proxies stays Rust. Today `services/control-plane` is about 13,000 lines of Rust (axum, sqlx). Product data (users, organizations, projects, environments, agents, settings) is ordinary tenant-scoped CRUD, the part of the API where a TypeScript framework gives the most speed and the widest contributor pool. Authorization decisions, token issuance, audit integrity and anything holding key material do not move without an owner decision (gates G1 and G2).

## What Changes

- A new app `apps/api`: NestJS 12 (ESM), TypeScript, Kysely over Postgres with the existing SQL migrations and row-level security, pg-boss jobs on Postgres (no Redis), pino logs, OpenTelemetry, health checks, OpenAPI generated from the same schemas that validate requests.
- Infisical's backend structure, adapted: one Nest module per domain (their `domains/<area>/<domain>` with a data-access store, service, controller and in-memory test doubles), a single composition root, guards for auth and permission, interceptors for audit and rate limits, a transaction runner that sets the tenant context.
- Tooling for all TypeScript in the repo through Turborepo: TypeScript, oxlint, oxfmt and knip (unused files, exports and dependencies), replacing ad hoc lint scripts.
- A strangler migration: both APIs run, a path-based route table sends each `/v1/...` path to the implementation that owns it, and a path moves only when the NestJS module passes the contract tests recorded from the Rust one.
- A defined Rust boundary: a small internal API (the "core") for the operations that stay in Rust, so the NestJS code never holds plaintext secrets or key material.
- Updating `openspec/config.yaml` and `AGENTS.md` (stack and licence lines, now stale; protected files, harness-release branch).

Out of scope: rewriting the gateway, `ls-crypto`, `ls-envelope`, `ls-audit` or the desktop daemon; changing the OpenAPI contract, database schema or any URL; GraphQL; microservice splitting; the hosted SaaS services (planned in `locksmith-cloud`, which follow OC-8 separately); any change to the web console beyond switching its API base through the route table.

Depends on: none (Rust control-plane changes in flight, t6, t7 and t8, finish first or are ported; gate G2).

## Capabilities

### New Capabilities
- `api-backend`: the HTTP API served by NestJS, its Rust boundary, tenant isolation, and the contract-parity rule for migrating endpoints from Rust.

### Modified Capabilities

## Impact

- Code: new `apps/api`; `turbo.json`; root lint, format and knip config; `scripts/tree-check.sh` (allow `apps/api`); `justfile` recipes; CI jobs; later a route table in the deploy config.
- Docs: `openspec/config.yaml` and `AGENTS.md` (stack and licence lines), `docs/testing.md`.
- Licence: `apps/api` is a server component, AGPL-3.0-only like `services/` (decision G4).
