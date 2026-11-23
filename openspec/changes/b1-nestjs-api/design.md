# Design: B1 NestJS API

## Context

**Observed in Infisical's backend** (github.com/infisical/infisical, read 2026-11-22; `backend/package.json`, `backend/src/**`, `backend/src/domains/AGENTS.md`):

| Area | What they do |
|---|---|
| Framework | Fastify 5 with hand-wired dependency injection; Node 26, TypeScript 7.0.2, vitest 3, tsx |
| Data | Knex over `pg`; migrations under `src/db/migrations`, separate migration runners for the audit-log database and ClickHouse; row types generated into `src/db/schemas` |
| Validation and API docs | zod schemas, `fastify-zod`, `@fastify/swagger`, versioned routes `v1` to `v4` |
| Auth and permissions | `jose` and `jsonwebtoken`, CASL abilities, plugins for auth, audit log, rate limits and IP rules |
| Jobs | BullMQ on Redis, a queue and cron layer in `src/queue` |
| Layout | Old: `src/services/*` (127 folders), `src/server/{plugins,routes}`, `src/ee`. New direction: `src/domains/<area>/<domain>/{ce,ee}` with one `domains.ts` composition root, a `lib/` of shared building blocks (errors, transaction runner, key store, jobs, data access), in-memory test doubles, and per-domain `AGENTS.md` |
| Beyond Node | A Go backend and sidecar for network-facing parts; Terraform provider, operator and agent injector in their own repos |

Observed in this repo: `services/control-plane` is Rust (axum, sqlx), about 12,900 source lines over 13 SQL migrations and a 37-path `openapi.json`, with tenant isolation by Postgres row-level security (decisions A0-4, A0-5). The web console and `packages/sdk` consume types generated from that spec.

Constraint from existing decisions: Postgres is the only required datastore (A0-1), jobs are a `FOR UPDATE SKIP LOCKED` table, no Redis or pgmq (A0-2), tenant context is set per transaction with `set_config('app.org_id', $1, true)` and session-level `SET` is banned (A0-5), UUIDv7 keys.

Assumption to verify (task 1.1): NestJS 12's official guide pins TypeScript `^6`; TypeScript 7 (the native compiler) is the current release, and Nest relies on decorators and `emitDecoratorMetadata`.

## Decisions and evidence

| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | NestJS 12, ESM, one module per domain | Fastify with hand-wired DI as Infisical does (their `domains.ts` hand-orders a growing graph; Nest's container does that); Express | Nest 12 makes every official package ESM and adds Standard Schema validation (dev.to NestJS 12 deep dive; docs.nestjs.com/migration-guide); Infisical's own AGENTS.md describes the wiring cost |
| 2 | Kysely plus generated types, SQL migrations stay the source of truth | Prisma or TypeORM (hide SQL, fight RLS and per-transaction `set_config`), Knex (what Infisical uses, weaker types) | A0-4, A0-5 need explicit transactions and plain SQL; kysely 0.29.9 and kysely-codegen are MIT; spike 1.5 proves RLS holds |
| 3 | pg-boss jobs on Postgres | BullMQ and Redis (Infisical's choice: a second datastore, extra $ in the dev budget), graphile-worker | A0-2 forbids Redis; pg-boss 12.39.0 MIT, last release 2026-11-21 |
| 4 | zod 4 schemas validate requests and generate OpenAPI | class-validator DTOs (decorator duplication) | Nest 12 Standard Schema support; Infisical does the same with zod |
| 5 | Strangler migration behind a path-based route table | Big-bang rewrite | About 13,000 lines and three changes still editing the Rust code; the 37-path spec makes per-path cut-over possible |
| 6 | A scenario suite run over real HTTP against both servers, with their normalised transcripts compared, is the acceptance suite | Recording the Rust integration tests (they call the router in-process with `tower::oneshot` from about 17 per-file helpers, 30 call sites, so no single recording hook exists); Schemathesis alone (checks the schema, not behaviour parity) | Read of `services/control-plane/tests/*.rs` on 2026-11-22; the Rust tests stay as the Rust unit and integration suite |
| 7 | Rust keeps plaintext secrets, keys and proxies: gateway, `ls-crypto`, `ls-envelope`, KMS access, audit signing | Moving them to Node (garbage-collected strings, no zeroize) | Owner rule in AGENTS.md; README security section |
| 8 | oxlint, oxfmt, knip on every TypeScript package, run by Turborepo | ESLint and Prettier | Owner decision 2026-11-22; versions below. oxfmt is pre-1.0 (0.79.0): pinned exactly, and formatting diffs are not review blockers |
| 9 | Pin TypeScript exactly; use 7.0.2 if the spike passes, else the latest 6.x | Assuming 7 works with Nest decorators | Gate G3 and spike 1.1 decide |

## OSS used

| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| @nestjs/core, common, testing | MIT | 12.6.0 | 2026-11-20 | Framework | not AGPL |
| @nestjs/swagger | MIT | 12.1.2 | 2026-11-13 | OpenAPI | not AGPL |
| @nestjs/terminus | MIT | 12.2.0 | 2026-11-16 | Health and readiness | not AGPL |
| nestjs-cls | MIT | 7.0.2 | 2026-10-27 | Request and tenant context (AsyncLocalStorage) | not AGPL |
| nestjs-pino | MIT | 5.3.2 | 2026-11-17 | Structured logs | not AGPL |
| kysely, kysely-codegen | MIT | 0.29.9, 0.20.0 | 2026-11-12, 2026-02-16 | Typed SQL | not AGPL |
| pg | MIT | 8.23.1 | 2026-09-30 | Postgres driver | not AGPL |
| pg-boss | MIT | 12.39.0 | 2026-11-21 | Jobs on Postgres | not AGPL |
| zod | MIT | 4.6.7 | 2026-10-12 | Schemas | not AGPL |
| jose | MIT | 6.2.18 | 2026-11-18 | JWT and JWKS verification | not AGPL |
| vitest | MIT | 5.1.1 | 2026-11-18 | Tests | not AGPL |
| testcontainers | MIT | 12.2.2 | 2026-11-19 | Throwaway Postgres for tests | not AGPL |
| typescript | Apache-2.0 | 7.0.2 | 2026-07-08 | Language (version per gate G3) | not AGPL |
| oxlint, oxfmt | MIT | 1.94.0, 0.79.0 | 2026-11-16 | Lint, format | not AGPL |
| knip | ISC | 6.47.0 | 2026-11-20 | Unused files, exports, dependencies | not AGPL |

Built in-house: the Rust core boundary (an internal HTTP API in the existing Rust workspace), the route table, the contract-test runner. Searched first: oasdiff (already used for the spec check) covers the schema, not behaviour, so behaviour parity needs the recorded-request runner.

## Architecture

- **Layout:** `apps/api/src/{main.ts, app.module.ts, platform/, domains/<area>/<domain>/{*.module,*.controller,*.service,*.store}.ts, db/, jobs/}`. A domain's store is the only code that issues SQL for its tables; other domains call its service. Each domain has an `AGENTS.md`, as in Infisical's `domains/`. In-memory stores and a fake job queue back the unit tests.
- **Request path:** auth guard (jose, issuers from config, same issuers and claims as the Rust `auth/` module) sets the principal; a tenant interceptor opens a transaction and runs `set_config('app.org_id', ..., true)`; permission guards read the principal's role; zod pipes validate; the audit interceptor emits audit events through the Rust core (below).
- **Rust boundary ("core"):** an internal-only HTTP API served by a Rust binary in this workspace, reachable only from the API's network. Default contents (gate G1): audit append and checkpoint signing, agent-token and workload-token mint and verify, DEK wrap and unwrap through KMS, secret-version encryption if the API ever receives plaintext (it must not: decision H1-1 seals in the browser). The NestJS code receives ciphertext, ids and verdicts, never plaintext values or key bytes.
- **Routing (strangler):** one route table (path prefix and method to `rust` or `nest`) in the deploy config and in the local compose proxy. A path flips only after its contract tests pass against the NestJS module; flipping back is a one-line change.
- **Migrations:** the existing `.sql` files stay authoritative and keep their order. One runner owns applying them (decided in task 2.3: the Rust migrator stays the only runner and `apps/api` only reads the schema; the embedded migrator in `services/control-plane` gets a small `locksmith-migrate` binary so tooling can migrate a throwaway database without starting the API), and `kysely-codegen` regenerates types from the migrated database into `apps/api/src/db/types.ts` (`just api-types`; `just api-types-check` fails on drift and is part of `just ci`). The generator starts a throwaway Postgres with a random password, runs `locksmith-migrate`, then introspects; the app connects through Kysely over `pg` using `DATABASE_URL` (the non-owner app role), never the owner URL. The migration guard (#623) covers both.
- **Tooling:** `apps/api` and the existing TypeScript packages share one `tsconfig` base, oxlint config, oxfmt config and knip config at the root; Turborepo tasks `lint`, `format`, `knip`, `typecheck`, `test`, `build`.

## How an agent debugs this

- MCP servers in `.mcp.json`: `postgres` (restricted) for tables and row-level-security policies; `grafana` for logs (Loki) and traces (Tempo).
- Commands: `just up`, `npm run dev --workspace apps/api`, `npx turbo run test --filter=@locksmith/api`, the contract runner `just api-contract <base-url>`, `just mcp-check`.
- Tables: `orgs`, `projects`, `environments`, `memberships`, `agents` and the audit tables; every request logs its trace id and org id.

## Risks

- TypeScript 7 with Nest decorators is unproven here (task 1.1). Fallback: TypeScript 6.x, pinned.
- oxfmt is pre-1.0; formatting may change between releases. Pinned.
- Two implementations during the migration double the surface for tenant-isolation bugs; the cross-tenant contract tests run against both on every PR.
- The Rust workers' changes keep landing until gate G2 is answered.
- A TypeScript API holds the database credentials for CRUD, so a Node dependency compromise reaches tenant data. Mitigations: row-level security with a non-owner role, pinned lockfile, knip and `npm audit` in CI, and plaintext secrets never present in this process.
