# Proposal: refactor-control-plane-api

## Why
The S1 resource API (PR #106) repeats the same code in every handler file, and S2–S4 will add more handlers on top of it. The OpenAPI document also describes timestamps as plain strings, so the SDKs P3 generates from it would type them as strings. Fixing both now means the next handlers extend shared code instead of copying it again.

Evidence (lead code review, 2026-11-17, at origin/main `2289bc4`):
- The OpenAPI error-response entry (`status = 4xx/503, body = Problem, content_type = "application/problem+json"`) is written out 68 times across `src/api/{projects,environments,secrets,orgs}.rs`.
- Optional-row mapping `.as_ref().map(from_row).transpose().map_err(ApiError::from)` appears 7 times; list collection 3 times; "deleted, else 404" 3 times; and `require_project` / `require_environment` are the same existence check.
- The `to_char(... 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')` timestamp SQL is in both `common_cols!` (`api/mod.rs`) and `cols!` (`api/orgs.rs`). Response types use `created_at: String`, and `openapi.json` has no `format: date-time`.

## What Changes
- Shared utoipa `IntoResponses` error sets (for example read, write and delete errors) replace the per-route error lists.
- Small helpers in `src/api/mod.rs` replace the repeated row-mapping, list, delete and parent-exists code.
- Timestamps are decoded as `time::OffsetDateTime` through sqlx-postgres's `time` feature and serialized as RFC 3339 UTC. The OpenAPI schema gains `format: date-time`, and the `to_char` SQL is removed.
- `openapi.json` is regenerated. The only intended differences are `format: date-time` and the shared response components.

Usable outcome: a new resource handler (S2 secret versions, S4 agents) is written by calling the shared helpers and response sets, and generated SDKs get typed timestamps.

Out of scope: new endpoints, any change to status codes, problem types, paths or pagination, a repository layer, and the S2 version model.

Depends on: s1-control-plane-skeleton (archived).

## Capabilities

### New Capabilities
None.

### Modified Capabilities
None. `control-plane-api` already requires RFC 3339 UTC timestamps, and the status codes and bodies stay the same, so `.openspec.yaml` sets `skip_specs: true`.

## Impact
- Code: `services/control-plane/src/api/*.rs`, `services/control-plane/Cargo.toml` (adds the `time` feature on sqlx-core/sqlx-postgres, and `time` with `serde` and `formatting`; `time` 0.3.55 is already in `Cargo.lock`), and `services/control-plane/openapi.json`.
- Wire format: timestamps stay RFC 3339 UTC. Fractional seconds may print with fewer than 6 digits (for example `.12Z` instead of `.120000Z`). This is still valid RFC 3339, and `tests/api.rs` `assert_rfc3339_utc` must still pass.
- No migration and no data change.
