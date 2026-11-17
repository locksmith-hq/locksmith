# Tasks: refactor-control-plane-api

## 1. Shared handler helpers
- [ ] 1.1 Add `one`, `all`, `deleted_or_404` and `exists_or_404` in `services/control-plane/src/api/mod.rs` (design decision 2). Replace the 7 optional-row mappings, 3 list collections, 3 delete branches, and `require_project` / `require_environment` in `environments.rs`, `orgs.rs`, `projects.rs` and `secrets.rs`.
- [ ] 1.2 Verify: `cargo nextest run -p ls-control-plane` passes and `cargo clippy -p ls-control-plane --all-targets -- -D warnings` is clean, with no test edited.

## 2. Shared OpenAPI error responses
- [ ] 2.1 Define shared error sets with `#[derive(utoipa::IntoResponses)]` (design decision 1) and use them in every `#[utoipa::path]` in `src/api/`. No route may list a `problem+json` response by hand afterwards (`grep -c 'application/problem+json' src/api/*.rs` is 0 outside the shared definitions).
- [ ] 2.2 Verify: `UPDATE_OPENAPI=1 cargo nextest run -p ls-control-plane -E 'test(openapi)'`, then `git diff services/control-plane/openapi.json` shows no change to paths, status codes or schema names; `cargo nextest run -p ls-control-plane` passes.

## 3. Typed timestamps
- [ ] 3.1 Enable the `time` feature on sqlx-core and sqlx-postgres and add `time` (0.3.55, `serde`, `formatting`) to `services/control-plane/Cargo.toml`. Decode `created_at` / `updated_at` as `OffsetDateTime` in UTC and serialize as RFC 3339 (design decisions 3 and 4). Remove the `to_char` SQL from `common_cols!` and `orgs.rs` `cols!`.
- [ ] 3.2 Regenerate `openapi.json`. Every `created_at` and `updated_at` schema has `"format": "date-time"`.
- [ ] 3.3 Verify: `cargo nextest run -p ls-control-plane` passes (including `assert_rfc3339_utc`), and `cargo deny check` is clean.

## 4. Local verification
- [ ] 4.1 `just up`, then `just api` in the background, `cargo nextest run -p ls-e2e --test api`, `just leak-scan`, and `just ci`.
