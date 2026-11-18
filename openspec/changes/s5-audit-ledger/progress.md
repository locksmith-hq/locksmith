# Progress: s5-audit-ledger

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-17 23:00 worker
- Task: none - planning
- Verified: `openspec validate s5-audit-ledger --strict`, `bash scripts/tree-check.sh`
- Notes for next session: depends on s4-agent-connector (and through it s3-gateway-http, PR 168). Groups 1-5 are [opus] (audit path). Group 1 must keep the `ls-vault` audit bytes identical (golden vectors first). Re-check sha2, serde_json and tempfile release dates on crates.io, and AWS KMS Ed25519 support for P1. Open question for the owner: when the S3 Object Lock sink lands (proposed for P1).

## 2026-11-17 21:55 lead
- Task: none (code review of the merged S3 gateway, for S5 2.x-3.x)
- Finding: Postgres test setup is duplicated. `services/gateway/tests/audit_pg.rs:17-28,51-71` repeats `Pg::start`, `Pg::options`, `Pg::migrated` and `Pg::app_db` from `services/control-plane/tests/common/mod.rs:22-95`. The ledger tests (2.4, 3.2) need the same harness: share it (a `testing` feature or test-support crate) instead of making a third copy.
- Finding: replace `PgAudit` behind the existing `AuditSink` trait (`services/gateway/src/relay.rs:46`) so `relay.rs` barely changes. Don't extend the `gateway_audit` writer, since 3.1 removes it.
- Carried from the PR 191 merge review (agent-log 2026-11-17 20:27Z): outcome retries need an idempotency key on the attempt id, and the rollback must either keep a gated legacy writer or be documented as a code revert. Add both to design.md before task 3.1.
- Notes for next session: the shared e2e helpers (`api`, `wiremock`, `uniq`, `mint_canary`) now live in `tests/e2e/src/lib.rs` (lead PR); use them for 7.1.
