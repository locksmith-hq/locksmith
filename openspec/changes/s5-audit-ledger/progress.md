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

## 2026-11-18 11:30 worker
- Task: 1.1-1.3 - done
- Verified: `just ci` -> green; `cargo nextest run -p ls-audit -p ls-vault` -> 37 passed (golden vectors written before the switch, pass on old and new code)
- Notes for next session: group 2 next (Postgres ledger, migrations, store). `ls-audit::row_hash(canonical, suffix)` takes an empty suffix for the server ledger (no MAC). Run `npm ci` before `just ci` or web lint fails on the missing control-plane-client link. Reuse the Pg test harness from control-plane tests (see lead finding above).

## 2026-11-18 15:30 worker
- Task: 2.1 (migration, all but one item; not ticked), 2.2 - done
- Verified: `cargo nextest run -p ls-audit --features postgres -p ls-control-plane -p ls-gateway -p ls-pg-test -p ls-vault` -> 180 passed (incl. 50 concurrent appends -> seq 1..50 with intact links, app-role UPDATE/DELETE refused on events/checkpoints/verify runs/heads, RLS+FORCE and cross-org isolation on all four tables, verifier role); `cargo clippy --workspace --all-targets -D warnings` (and `-p ls-audit --features postgres`), `cargo fmt --check`, tree-check, task guard, `cargo deny check` -> ok
- Done: `migrations/0008_audit_ledger.sql` (`audit_heads`, `audit_events`, `audit_checkpoints`, `audit_verify_runs`, `audit_verifier` role); `ls-audit::event` (allow-listed `Code`/`Actor`/`Target`/`Host`/`AttrValue`, `Record` encoding with a golden vector cross-checked in Python); `ls-audit::pg` (feature `postgres`: `PgLedger::append`, `append_in_tx` for appending inside a caller's `with_org` transaction, `records_in_tx`, `checkpoints_in_tx`). New test-support crate `crates/ls-pg-test` (lead finding): control-plane and gateway tests now use it instead of their own container setup.
- Open: 2.1's "revoke INSERT on `gateway_audit`" is NOT in 0008. The gateway still writes `gateway_audit` and fails closed (`audit_failed`) when that write fails, so revoking now breaks every relay and `audit_pg` until 3.1. Land the revoke as its own migration in the same commit as 3.1, then tick 2.1.
- Notes for next session: the `postgres` feature is not enabled by any workspace crate yet, so `just test-rust` skips `crates/ls-audit/tests/pg.rs` until 2.3 adds the control-plane dependency; run it with `--features postgres`.

## 2026-11-18 13:50 worker
- Task: 2.3 (and the 2.4 control-plane tests) - done; 2.4 not ticked (the app-role UPDATE/DELETE and RLS checks sit in the 2.2 pg tests, which run once `postgres` is enabled; 2.4 can be ticked after confirming)
- Verified: `just ci` -> green; `cargo nextest run -p ls-audit --features postgres -p ls-control-plane` -> 104 passed; evaluator (Opus) PASS
- Done: `services/control-plane/src/audit.rs`; agent create/rotate/delete and grant create/revoke append in the same `with_org` tx; `POST /internal/v1/audit/events` behind the service token (closed enums, `Host::parse`, kind/outcome pairing); openapi.json and TS schema regenerated; `ls-audit` `postgres` feature now enabled by control-plane.
- Open: (1) deleting a secret cascades grants without a `grant.revoked` event (S2 route, consider a `secret.deleted` event); (2) outcome-retry idempotency on attempt id is still for 3.1/design.md; (3) `host` is the one non-closed attribute (host-name-shaped strings pass); (4) agent delete counts grants with a separate SELECT before DELETE, so lock the agent row for an exact count; (5) dev auth actor is `Service("dev_auth")` until T1 gives `Actor::User`.
- Notes for next session: 2.4 verify, then 3.1 with the gateway `AuditSink` swap; land the `gateway_audit` revoke migration with 3.1 and tick 2.1 then.

## 2026-11-18 14:11 worker
- Task: 2.4 - done
- Verified: `cargo nextest run -p ls-audit --features postgres -p ls-control-plane` -> 104 passed (50 concurrent appends, app-role UPDATE/DELETE refused, RLS and cross-org isolation, 401 without service token, no canary in stored events)
- Notes for next session: 3.1 next ([opus], audit path): swap the gateway `AuditSink` (relay.rs) to call POST /internal/v1/audit/events, 503 fail-closed before unwrap, 3 outcome retries with an idempotency key on attempt id; add the rollback note to design.md first. Land the `gateway_audit` INSERT revoke migration with 3.1 and tick 2.1 then. Also open: secret.deleted event for cascaded grants.
