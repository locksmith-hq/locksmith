# Progress: B2 Rust core service

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-23 (PM, planning)
- Split out of `b1-nestjs-api` group 5 (tasks 5.2 and 5.3) so a second worker can build the Rust core while B1's NestJS foundation is in progress (#653, #670). B1 keeps 5.4 (the NestJS side calls `packages/core-client`) and 5.5. Nothing implemented.

## 2026-11-23 worker
- Task: 1.1-1.3 contract (services/core/openapi.json, packages/core-client with fixtures and drift test) - done
- Verified: `npx turbo run build test --filter=@locksmith/core-client` (6 tests), tree-check, `just quick`; Sonnet evaluator PASS
- Notes for next session: group 2 next (ls-core-service skeleton; docs/testing.md `services/core` row needs revising once the crate exists). Group 3 should tighten `AuditTarget` to the Rust enum (Org, Secret, Agent, Grant, WorkloadIdentity) and confirm `VerifyReason` extras (`unknown_key`, `not_trusted`) against `VerifyError`. wrapDek takes binding ids only; the core generates the DEK.
