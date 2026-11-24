# Proposal: B4 API contract suite

## Why

`b1-nestjs-api` (44 tasks, one worker) is in the `Needs` of five Phase 2 rows: T2, T6, T7, T8 and N1. The PM narrowed each of them to `b1-nestjs-api:contract` (B1 task group 1, "Contract and spikes"), so they can start against the frozen schema and fixtures instead of waiting weeks for the whole port. Three of that group's six tasks are open: 1.4 (scenario suite), 1.5 (runner and diff) and 1.6 (verify). They need only the Rust control plane from `just up`, nothing from `apps/api`, while B1's worker builds the NestJS skeleton (group 2, PR #674). This change moves them to a second worker.

## What Changes

- `tests/api-contract`: a vitest and `fetch` scenario suite, one data-driven file per resource; for every path and method in `services/control-plane/openapi.json` a success case, a validation error, a missing-token 401 and a cross-tenant 404 or 403, with ids, timestamps and tokens normalised in the recorded transcript (B1 design decision 6).
- `scripts/api-contract.sh <base-url>` writes the normalised transcript; `--diff <url-a> <url-b>` reports the first differing status, header or body field per path; `just api-contract`.
- A coverage test that fails when a path in `openapi.json` has no scenario.

**Usable outcome:** anyone (and B1's port tasks) can run `just api-contract http://127.0.0.1:8080` against the running control plane and get a deterministic transcript, and `--diff` shows exactly where a second server (the NestJS API) behaves differently.

Out of scope: any NestJS code (`apps/api`), the route table (B1 1.3, on #674), porting endpoints (B1 group 6), the compose proxy (B1 group 7), and changes to `openapi.json` or Rust behaviour.

Depends on: none. When this change merges, the B1 worker verifies and ticks B1 tasks 1.4 to 1.6 (B1 progress.md), which completes `b1-nestjs-api:contract`.

## Capabilities

### New Capabilities
- `api-contract`: a server-agnostic HTTP scenario suite and transcript diff for the control-plane API.

### Modified Capabilities

## Impact

- Code: new `tests/api-contract` (npm workspace), `scripts/api-contract.sh` and its test, `justfile` (`api-contract`), root `package.json` workspaces, `scripts/tree-check.sh` and `docs/testing.md` entries.
- No production code changes.
