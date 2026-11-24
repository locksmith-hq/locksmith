# Design: B4 API contract suite

## Context

B1 design decision 6 (`openspec/changes/b1-nestjs-api/design.md`) makes a scenario suite over real HTTP, run against both servers with normalised transcripts compared, the acceptance suite for the strangler port. The Rust integration tests cannot be recorded (they call the router in-process with `tower::oneshot` from about 17 per-file helpers). `services/control-plane/openapi.json` has 39 paths. `just api` runs the control plane on `127.0.0.1:8080` with dev auth (`LOCKSMITH_DEV_AUTH=1`); `scripts/auth-e2e.py` shows the Keycloak sign-in path.

## Decisions and evidence

| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | vitest and the built-in `fetch`, no client library | The generated `packages/control-plane-client` (it would hide status codes and headers the diff must see); supertest (in-process only) | B1 decision 6: "no framework coupling"; vitest is already used in `apps/web`, `apps/desktop`, `packages/control-plane-client` |
| 2 | One data-driven scenario file per resource, a shared seeding helper for two users in two orgs | One test per path written by hand | 39 paths x 4 cases; data rows keep the cases uniform and reviewable |
| 3 | Normalise ids, timestamps and tokens to stable placeholders in order of first appearance | Strip them | Keeps references between responses (the id created is the id read back) comparable across servers |
| 4 | Auth through the dev-auth path `just api` enables; Keycloak only if dev auth cannot cover a case | Keycloak for every scenario | Dev auth is deterministic and fast; T1 sign-in behaviour is covered by `just auth-e2e` |
| 5 | Internal paths (`/internal/v1/*`) are exercised with the gateway's internal credential and without it | Excluding them | They are part of what B1 must serve or route; excluding a path needs a reason in the coverage list |

## OSS used

| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| vitest | MIT | the workspace's `^4.1.12` | already in use | test runner | not AGPL |

No other packages. Built in-house: the normaliser and the diff (a few dozen lines of JSON walking); searched first for OpenAPI parity tools: Schemathesis checks schema conformance, not behaviour parity between two servers (B1 decision 6).

## How an agent debugs this

- `just up`, `just api`, then `just api-contract http://127.0.0.1:8080`; the transcript is written under `target/api-contract/`.
- `scripts/api-contract.sh --diff <a> <b>` prints the first difference per path.
- MCP: `grafana` (Loki logs and Tempo traces of the control plane for a failing request), `postgres` (restricted) for seeded rows.

## Risks

- Non-deterministic fields not caught by the normaliser make the transcript flaky: task 4.1 runs the suite twice and requires identical output.
- Scenarios write data: each run seeds fresh orgs with unique names, so reruns against the same database stay independent.
