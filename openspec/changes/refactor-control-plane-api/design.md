# Design: refactor-control-plane-api

## Context
See proposal.md (Why). Handlers in `services/control-plane/src/api/` run SQL directly inside the `with_org` tenant transaction (S1 design decision 5). This is the same in every file, and this change keeps it. The duplication is in the glue around that SQL and in the utoipa annotations.

## Goals / Non-Goals
- Goal: one place for each repeated pattern; `openapi.json` changes only by `format: date-time` and shared response components.
- Non-goal: a repository layer, new error kinds, any change to status codes, problem `type` URIs, paths or pagination.

## Decisions

| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | Shared error sets as `#[derive(utoipa::IntoResponses)]` enums or structs, referenced from `#[utoipa::path(responses(...))]` | Keep per-route lists (68 copies now, more per S2–S4 handler); a declarative macro (hides the spec from utoipa's checks) | utoipa 6.0.0 `IntoResponses` derive, https://docs.rs/utoipa/6.0.0/utoipa/derive.IntoResponses.html |
| 2 | Helpers `one`, `all`, `deleted_or_404` and `exists_or_404` in `api/mod.rs`, taking the row mapper as a closure | A generic `Resource` trait with CRUD defaults (more abstraction than three resources justify) | 7, 3, 3 and 2 copies listed in proposal.md |
| 3 | Decode `timestamptz` into `time::OffsetDateTime` through the sqlx `time` feature; serialize with `time::serde::rfc3339`; mark the schema `#[schema(value_type = String, format = DateTime)]` | Keep `to_char` strings (no `format` in OpenAPI, SQL repeated); `chrono` (`time` is already in `Cargo.lock`, so no new crate) | sqlx-postgres `time` feature types, https://docs.rs/sqlx-postgres/0.9.0/sqlx_postgres/types/index.html ; `time::serde::rfc3339`, https://docs.rs/time/0.3.55/time/serde/rfc3339/index.html |
| 4 | Convert to UTC before serializing (`to_offset(UtcOffset::UTC)`) | Trust the session time zone | The spec requires RFC 3339 UTC, and `timestamptz` decodes in the session offset |

## OSS used

| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| utoipa | MIT/Apache-2.0 | 6.0.0 | 2026-09-22 | `IntoResponses` derive (already a dependency) | not AGPL |
| sqlx-core, sqlx-postgres | MIT/Apache-2.0 | 0.9.0 | 2026-05-21 | `time` feature for `timestamptz` (already a dependency) | not AGPL |
| time | MIT/Apache-2.0 | 0.3.55 | 2026-08-01 | `OffsetDateTime` and its RFC 3339 serde (already in `Cargo.lock`) | not AGPL |

Built in-house: only the four small helpers in decision 2, which are glue around our own `with_org` and `ApiError` and have no crate equivalent.

## Risks / Trade-offs
- [Fractional seconds print with fewer than 6 digits] → still RFC 3339. `assert_rfc3339_utc` in `tests/api.rs` and the e2e suite must pass unchanged.
- [`openapi.json` snapshot drift] → regenerate with `UPDATE_OPENAPI=1` and check the diff only adds `format: date-time` and shared responses. Any path, status or schema-name change is a bug.
- [`IntoResponses` puts response descriptions in one place] → keep the existing description text so the generated docs read the same.

## Migration Plan
No data migration. The change is code only and is reverted with `git revert`.

## How an agent debugs this
- `just up`, then `just api` in the background; `curl -s localhost:<port>/openapi.json | jq '.components.schemas.Project.properties.created_at'`.
- `cargo nextest run -p ls-control-plane -E 'test(openapi)'` prints the snapshot diff.
- The `postgres` MCP server: `SELECT created_at FROM projects LIMIT 1` to compare with the API's value.
- Traces in Tempo through the `grafana` MCP server (`service.name=locksmith-api`) if a handler regresses.
