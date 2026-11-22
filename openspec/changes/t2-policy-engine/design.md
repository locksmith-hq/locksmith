# Design: T2 policy engine

## Context
- Today: `OrgBinding` scopes every control-plane request to one org; after T6 it also carries the caller's `OrgRole`. Apart from T6 member management, any member may call any route.
- Agent grants (`agent_grants`, migration `0006_agents.sql`) have one mode, `relay`; the gateway reads them from the control plane's internal grants endpoint and caches them for at most `MAX_CACHE_TTL` (10 s, `services/gateway/src/ttl.rs`) before `/v1/relay` checks `allows_relay`.
- Delegated paths exist (`smith git`, `smith aws` via D2, `smith db` via D3) and human injection exists (`smith run`, whose help text already warns never to inject into an agent).

## Decisions and evidence
| Decision | Alternatives rejected | Evidence |
|---|---|---|
| Cedar in-process via `cedar-policy` in a new `crates/ls-policy` | OPA/Rego (`regorus`): harder to author, no schema validation of the same strength; OpenFGA, SpiceDB, OPA server: extra process, breaks "Postgres is the only required datastore" | `docs/research/oss-building-blocks.md` (Authz row); Cedar docs https://docs.cedarpolicy.com/ (schema validation, `forbid` overrides `permit`) |
| The control plane is the one decision point; the gateway gets already-decided grants | Embed `ls-policy` in the gateway and ship policies plus entities to it | One place to evaluate and audit; the gateway already trusts the grants endpoint. Time-based rules are then precise to the 10 s grant cache, which is the same bound as revocation today (S4 design decision 4) |
| Built-in role policies are code (`ls-policy/policies/*.cedar`, embedded with `include_str!`), org policies are rows | Store built-ins in the DB | Built-ins must not be editable or deletable; versioned with the binary and covered by unit tests |
| `forbid` for `inject` by `Agent` is built in | Enforce only in the grant handler | Cedar's `forbid` always wins over any `permit`, so no org policy can undo it; matches the AGENTS.md rule "agents never receive secret values" |
| ABAC attributes: org, project and environment names, secret name, agent name, grant mode, role, `context.now` (hour, weekday UTC) | Free-form tags on environments and secrets | No schema change to existing tables; tags can be a later, separate change |
| Deny is `403 policy-denied` with no policy text; the deciding ids go to the ledger and the check endpoint | Return the deciding policy in the error | Policy text can reveal org structure to members; owners and admins get it through `/v1/policies/check` |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| `cedar-policy` | Apache-2.0 | 4.14.1 (pin at apply; re-check with `cargo search`) | 2026-11-02 | Policy language, schema validator, evaluator | Apache-2.0, fine in server components |

The policy editor is a plain `<textarea>` with server-side validation, so no editor package is added. Nothing is built in-house except the thin adapter (entity building from Postgres rows, mapping routes to actions).

## Cedar model
- Entity types: `User`, `Agent`, `Org`, `Project`, `Environment`, `Secret`. `User` has `role` per org in the request context (`context.role`), since the binding already resolved it. `Secret in Environment in Project in Org`.
- Actions, human: `org.manage`, `policy.manage`, `member.manage`, `project.write`, `environment.write`, `secret.read_meta`, `secret.write`, `secret.delete`, `agent.manage`, `grant.manage`, `audit.read`.
- Actions, agent use: `use.relay`, `use.delegate`, `use.inject`.
- Built-in files: `roles.cedar` (owner, admin, member permits), `guards.cedar` (`forbid (principal is Agent, action == Action::"use.inject", resource);`, and grant creation of mode `inject` for an agent principal).
- Agent use is allowed only when a grant exists for that secret with that mode (`context.grant_modes` contains the mode) and no forbid matches.

## Data model
- `org_policies` (org_id, id, name, cedar_text, version, created_by, created_at, deleted_at): forced RLS like the other org tables; every update inserts a new version row. Migration number: the next free one at apply (T6 uses `0014`).
- `agent_grants.mode` CHECK widened to `relay|delegate|inject`; existing rows stay `relay`.

## API (contract group)
- `GET /v1/policies` (built-in and org), `POST /v1/policies`, `PUT /v1/policies/{id}`, `DELETE /v1/policies/{id}`: owners only for writes; `422` carries the Cedar validation message.
- `POST /v1/policies/check` `{principal: {type, id}, action, resource: {type, id}}` -> `{decision, policy_ids}`: owners and admins.
- `GrantMode` gains `delegate` and `inject` in the OpenAPI schema and in `packages/control-plane-client`.
- Problem slug `policy-denied` (403).

## Risks
- Missing a route: a route not mapped to an action would skip authorization. Mitigation: one `authorize(action)` extractor used by every handler, and a test that walks the OpenAPI document and fails on any route without an action.
- Evaluation cost: Cedar evaluates in microseconds for small policy sets; the policy set per org is loaded once per request from Postgres. If this shows up in traces, cache per org with the same 10 s bound.
- Time rules precision is bounded by the 10 s gateway grant cache (documented in the spec scenario and the console help text).

## Open questions
- None blocking. Custom roles and tags are deliberately later changes.

## How an agent debugs this
- `just up`, then `just psql` and `SELECT * FROM org_policies` / `SELECT mode, count(*) FROM agent_grants GROUP BY 1`.
- `cargo nextest run -p ls-policy` runs the built-in policy tests; `cargo nextest run -p ls-control-plane policy` the route tests.
- Every deny writes a ledger event `policy.denied` with action and policy ids; read it with `just audit-verify` and the audit MCP/`GET /v1/audit`.
- Traces: span `policy.decide` with attributes `action`, `decision`, `policy_count` (no entity names) in the local OTel stack.
