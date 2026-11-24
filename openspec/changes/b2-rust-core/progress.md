# Progress: B2 Rust core service

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-23 (PM, planning)
- Split out of `b1-nestjs-api` group 5 (tasks 5.2 and 5.3) so a second worker can build the Rust core while B1's NestJS foundation is in progress (#653, #670). B1 keeps 5.4 (the NestJS side calls `packages/core-client`) and 5.5. Nothing implemented.

## 2026-11-23 worker
- Task: 1.1-1.3 contract (services/core/openapi.json, packages/core-client with fixtures and drift test) - done
- Verified: `npx turbo run build test --filter=@locksmith/core-client` (6 tests), tree-check, `just quick`; Sonnet evaluator PASS
- Notes for next session: group 2 next (ls-core-service skeleton; docs/testing.md `services/core` row needs revising once the crate exists). Group 3 should tighten `AuditTarget` to the Rust enum (Org, Secret, Agent, Grant, WorkloadIdentity) and confirm `VerifyReason` extras (`unknown_key`, `not_trusted`) against `VerifyError`. wrapDek takes binding ids only; the core generates the DEK.

## 2026-11-23 worker-a
- Fixed red CI on PR #687: services/core has only openapi.json so the `services/*` workspace glob failed; excluded it in Cargo.toml until task 2.1 adds the crate (remove the exclude then).

## 2026-11-24 worker-a
- Merged main into the branch (conflict in docs/testing.md only). Task 2.1-2.3 done: `services/core` crate `ls-core-service` (bin `locksmith-core`): `/healthz`, `/readyz`, service-token auth middleware (design decision 5), config, telemetry (copied from the control plane with `service_name` option; shared crate is a later cleanup), 9 tests incl. 401 without token.
- Verified: `cargo nextest run -p ls-core-service` (9 pass), clippy -D warnings, tree-check, `just test core` path.
- Notes for next session: group 3. The auth layer is applied with `.layer` on an empty internal router; mount operation routes there. Shared code for 3.1 needs a library crate moved out of control-plane `audit.rs`/`checkpoint.rs`; this is a big move, slice per operation.
