# Design: T2 policy engine

## Context
- Decision OC-9 (G1): authorization decisions live in the NestJS API (`apps/api`, change `b1-nestjs-api`); the Rust core keeps only audit signing, token mint and verify, and key wrap. This change therefore builds on B1's ported endpoints, its auth and permission guards (b1 tasks 4.1 and 4.3) and its core client for ledger events (b1 task 5.4). T6 is rebuilt in NestJS after the B1 port (OC-9 G2); its contract group supplies the `OrgRole` type.
- Today: the request's org binding scopes every API request to one org; after T6 it also carries the caller's `OrgRole`. Apart from T6 member management, any member may call any route.
- Agent grants (`agent_grants`, migration `0006_agents.sql`) have one mode, `relay`; the gateway reads them from the control plane's internal grants endpoint and caches them for at most `MAX_CACHE_TTL` (10 s, `services/gateway/src/ttl.rs`) before `/v1/relay` checks `allows_relay`.
- Delegated paths exist (`smith git`, `smith aws` via D2, `smith db` via D3) and human injection exists (`smith run`, whose help text already warns never to inject into an agent).

## Decisions and evidence
| Decision | Alternatives rejected | Evidence |
|---|---|---|
| Cedar in-process in the NestJS API via `@cedar-policy/cedar-wasm` (the Cedar project's official WebAssembly build of the same Rust evaluator), in `apps/api/src/platform/policy` | A Rust `ls-policy` crate in the control plane (rejected: OC-9 G1 puts authorization in NestJS); a Rust policy sidecar behind the core API (extra hop on every request, and G1 kept the core to audit, tokens and keys); OPA/Rego, OpenFGA, SpiceDB: extra process or weaker schema validation, and break "Postgres is the only required datastore" | `docs/research/oss-building-blocks.md` (Authz row); Cedar docs https://docs.cedarpolicy.com/ (schema validation, `forbid` overrides `permit`); npm `@cedar-policy/cedar-wasm` 4.15.0, Apache-2.0, published 2026-11-16 from github.com/cedar-policy/cedar |
| The NestJS API is the one decision point; the gateway gets already-decided grants | Embed Cedar in the gateway and ship policies plus entities to it | One place to evaluate and audit; the gateway already trusts the grants endpoint. Time-based rules are then precise to the 10 s grant cache, which is the same bound as revocation today (S4 design decision 4) |
| Built-in role policies are code (`apps/api/src/platform/policy/*.cedar`, shipped with the build), org policies are rows | Store built-ins in the DB | Built-ins must not be editable or deletable; versioned with the binary and covered by unit tests |
| `forbid` for `inject` by `Agent` is built in | Enforce only in the grant handler | Cedar's `forbid` always wins over any `permit`, so no org policy can undo it; matches the AGENTS.md rule "agents never receive secret values" |
| ABAC attributes: org, project and environment names, secret name, agent name, grant mode, role, `context.now` (hour, weekday UTC) | Free-form tags on environments and secrets | No schema change to existing tables; tags can be a later, separate change |
| Deny is `403 policy-denied` with no policy text; the deciding ids go to the ledger and the check endpoint | Return the deciding policy in the error | Policy text can reveal org structure to members; owners and admins get it through `/v1/policies/check` |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| `@cedar-policy/cedar-wasm` | Apache-2.0 | 4.15.0 (pin exactly at apply; re-check with `npm view`) | 2026-11-16 | Policy language, schema validator, evaluator (WebAssembly build of `cedar-policy`) | Apache-2.0, fine in server components |

The policy editor is a plain `<textarea>` with server-side validation, so no editor package is added. Nothing is built in-house except the thin adapter (entity building from Postgres rows, mapping routes to actions).

## Cedar model
- Entity types: `User`, `Agent`, `Org`, `Project`, `Environment`, `Secret`. `User` has `role` per org in the request context (`context.role`), since the binding already resolved it. `Secret in Environment in Project in Org`.
- Actions, human: `org.manage`, `policy.manage`, `member.manage`, `project.write`, `environment.write`, `secret.read_meta`, `secret.write`, `secret.delete`, `agent.manage`, `grant.manage`, `audit.read`.
- Actions, agent use: `use.relay`, `use.delegate`, `use.inject`.
- Built-in files: `roles.cedar` (owner, admin, member permits), `guards.cedar` (`forbid (principal is Agent, action == Action::"use.inject", resource);`, and grant creation of mode `inject` for an agent principal).
- Agent use is allowed only when a grant exists for that secret with that mode (`context.grant_modes` contains the mode) and no forbid matches.

## Data model
- Migrations stay owned by the Rust `migrate` binary (b1 task 2.3); the API reads the tables through Kysely types from `just api-types`.
- `org_policies` (org_id, id, name, cedar_text, version, created_by, created_at, deleted_at): forced RLS like the other org tables; every update inserts a new version row. Migration number: the next free one at apply.
- `agent_grants.mode` CHECK widened to `relay|delegate|inject`; existing rows stay `relay`.

## API (contract group)
- All paths are NestJS (`nest` in `apps/api/route-table.json`), defined as zod schemas and checked against `services/control-plane/openapi.json` by B1's drift check.
- `GET /v1/policies` (built-in and org), `POST /v1/policies`, `PUT /v1/policies/{id}`, `DELETE /v1/policies/{id}`: owners only for writes; `422` carries the Cedar validation message.
- `POST /v1/policies/check` `{principal: {type, id}, action, resource: {type, id}}` -> `{decision, policy_ids}`: owners and admins.
- `GrantMode` gains `delegate` and `inject` in the OpenAPI schema and in `packages/control-plane-client`.
- Problem slug `policy-denied` (403).

## Risks
- Missing a route: a route not mapped to an action would skip authorization. Mitigation: one `@Authorize(action)` decorator and `PolicyGuard` on every controller, and a test that walks the generated OpenAPI document and fails on any `nest` route without an action. Routes still served by Rust during the strangler keep their existing checks until ported.
- WebAssembly start-up: the module loads once per process at boot; the readiness probe (`/readyz`) waits for it.
- Evaluation cost: Cedar evaluates in microseconds for small policy sets; the policy set per org is loaded once per request from Postgres. If this shows up in traces, cache per org with the same 10 s bound.
- Time rules precision is bounded by the 10 s gateway grant cache (documented in the spec scenario and the console help text).

## Open questions
- None blocking. Custom roles and tags are deliberately later changes.
- Human `inject` (`smith run`) needs no grant row: it is the action `use.inject` with a `User` principal, permitted by the role policies for members of the org (the review note on #614). Only agents use grants.

## How an agent debugs this
- `just up`, then `just psql` and `SELECT * FROM org_policies` / `SELECT mode, count(*) FROM agent_grants GROUP BY 1`.
- `npx turbo run test --filter=@locksmith/api -- policy` runs the built-in policy and route tests; `cargo nextest run -p ls-gateway grants` the gateway side.
- Every deny writes a ledger event `policy.denied` with action and policy ids; read it with `just audit-verify` and the audit MCP/`GET /v1/audit`.
- Traces: span `policy.decide` with attributes `action`, `decision`, `policy_count` (no entity names) in the local OTel stack.
