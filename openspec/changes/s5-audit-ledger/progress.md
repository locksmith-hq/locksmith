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

## 2026-11-18 17:30 worker
- Task: 3.1, 3.2 - implemented and verified; not ticked (lead ticks after review). 2.1's `gateway_audit` revoke now landed (migration 0009), so 2.1 can be ticked with 3.1.
- Verified: `cargo nextest run -p ls-audit --features postgres -p ls-control-plane -p ls-gateway -p ls-pg-test -p ls-vault` -> 189 passed; `cargo clippy --workspace --all-targets -D warnings` (and `-p ls-audit --features postgres`), `cargo fmt --check`, tree-check, task guard -> ok
- Done: design.md rollback note (code revert plus a forward re-grant migration; no gated legacy writer) and outcome idempotency, written before code. Gateway `HttpAudit` replaces `PgAudit` behind `AuditSink`: `relay.denied` for refusals, `relay.attempt` before material fetch/unwrap (`503 audit_unavailable` on failure), `relay.outcome` with `attempt_id`, 3 retries with backoff. Host recorded only after the origin matched the binding. Control plane: `relay.outcome` requires `attempt_id`, is idempotent under the head lock (200 same event, 409 different), backed by a partial unique index; migration 0009 revokes INSERT on `gateway_audit`. openapi.json and TS schema regenerated. `services/gateway/tests/audit_pg.rs` removed; ledger tests now run the real control plane in-process in `relay::tests`.
- Open: (1) the gateway still opens a Postgres pool only for readiness; consider readiness on the control plane instead and dropping `DATABASE_URL` from the gateway. (2) The endpoint does not check that `attempt_id` names a stored `relay.attempt` of the same agent and secret. (3) `relay.denied` is one try, no retry (no idempotency key). (4) Non-standard upstream methods are recorded without `method`.
- Notes for next session: group 4 (signed checkpoints) next.

## 2026-11-18 15:28 worker
- Task: 2.1, 3.1, 3.2 - done
- Verified: `just ci` -> green (617 passed, 4 skipped); evaluator (Opus) PASS on 942b84c
- Notes for next session: group 4 next (OpenBao audit-checkpoint key, checkpoint job). Before archiving, fix spec wording: specs/gateway-http-relay/spec.md:6 says every attempt names the upstream host, but refusals before the origin check omit it by design. Open: attempt_id is not checked against a stored attempt; relay.denied not retried; gateway keeps a PG pool only for readiness.

## 2026-11-18 worker (alfie)
- Task: 4.1, 4.2, 4.3 - done
- Verified: `just ci` -> green (636 tests); `cargo nextest run -p ls-audit --features postgres -p ls-control-plane -p ls-envelope -p ls-gateway -p ls-pg-test` -> 222 passed; live OpenBao 2.7.2 checks passed (sign-only token, key not exportable); gitleaks clean; evaluator (Opus) PASS
- Done: `ls-audit` checkpoint bytes (`locksmith-checkpoint-v1`, golden vector `tests/fixtures/checkpoint-v1.json`); `ls-envelope` `TransitSigner`; control-plane checkpoint job (migration 0010 `audit_checkpoint_jobs`, SKIP LOCKED, 1000 events or 60 s); `openbao-init.sh` key, policy and token; `just up` writes `infra/compose/.audit-verifier.json`.
- Open (evaluator nits): (1) 0010 `job_claim_*` policies use `USING true`; harden to `current_org_id() IS NULL`. (2) `db.rs` `without_org` doc no longer true for the jobs table. (3) check `rows_affected() == 1` on the `checked_at` update. (4) the job holds a pooled connection during the OpenBao call. (5) dev OpenBao is in-memory, so a restart makes older checkpoints unverifiable. (6) the control plane cannot verify a signature before storing it; 5.1 will catch it.
- Notes for next session: group 5 (`locksmith-audit` verify/export CLI) next; the disk filled once, so build with `CARGO_INCREMENTAL=0` and clear `target/` if needed.

## 2026-11-18 16:55 worker (josie)
- Task: 5.1 - done
- Verified: `just ci` -> green (664 tests); `cargo nextest run -p ls-audit` 38 passed, `-p locksmith-audit` 14 passed (live postgres:18 --db tests); evaluator (Opus) PASS on 0c43c2f
- Done: new crate `crates/locksmith-audit` (verify --db/--dir/--json, exit 0/1/2); pure logic in `ls-audit` (verifier.rs, export.rs line format for 5.2 to reuse, SignedCheckpoint).
- Open (nits): (1) undecodable rows under --db exit 2 without org/seq or run row; (2) a mid-run error records no verify rows; (3) --database-url shows in ps, prefer the env var; (4) --dir silently skips non-UUID dirs; (5) --db does not compare audit_heads.seq with last event seq; (6) --checkpoints-from not yet implemented (belongs to 5.3); (7) --dir runs are not recorded.
- Notes for next session: 5.2 export must use `ls-audit::export` so exporter and verifier agree; then 5.3 (just recipes, tamper test, --checkpoints-from). Build with CARGO_INCREMENTAL=0.

## 2026-11-18 worker (josie)
- Task: 5.2 - done
- Verified: `cargo nextest run -p ls-audit -p locksmith-audit` 66 passed; fmt and clippy clean; evaluator (Opus) PASS
- Done: `locksmith-audit export --dir` behind an `AuditSink` trait (`FileSink`): per-org JSON Lines via `ls_audit::export`, checkpoints.jsonl, cursor as commit point, temp+fsync+rename, lock file, crash recovery, `check_batch` refuses overlap or rewritten history.
- Open (nits): (1) cursor is per org at `<org_id>/cursor.json`; 5.3 and 7.1 must use that path. (2) `verify --dir` ignores the cursor, so an uncommitted tail from a crashed export is verified until the next export cleans it. (3) `check_batch` does not compare a checkpoint's hash to the exported event. (4) one long read-only transaction across all orgs. (5) tail deletion in the DB is not reported by export (verify and 5.3 tamper test cover it).
- Notes for next session: 5.3 next (just audit-verify/audit-export/audit-tamper-test, `--checkpoints-from`). Build with CARGO_INCREMENTAL=0.

## 2026-11-18 worker (josie)
- Task: 5.3 - done
- Verified: `just ci` -> green (675 passed, 5 skipped); `just audit-tamper-test` 2/2 against compose Postgres; evaluator (Opus) PASS
- Done: `verify --db --checkpoints-from <dir>` (export checkpoints join the DB ones; export-only orgs verified); `just audit-export`, `audit-verify` (runs --db --checkpoints-from, then --dir), `audit-tamper-test`; Rust tamper test (`tests/tamper.rs`) covers field edit, row delete, seq swap, truncation, exported line edit, and rewrite-with-recomputed-hashes plus deleted checkpoint rows (caught only with export checkpoints).
- Open (nits): (1) `audit_verify_runs` row records ok=true when only an unreadable exported checkpoint line failed. (2) `just audit-verify --json` prints two JSON documents. (3) recipe comments show oddly in `just --list`. (4) rewrite between last exported checkpoint and export cursor is caught by --dir, not --db --checkpoints-from (audit-verify runs both). (5) owner deleting an export-only org's `orgs` row makes verify exit 2 not 1.
- Notes for next session: 5.4 (`just up && just audit-tamper-test`, full stack with OpenBao) then group 6 (API, web, desktop). Build with CARGO_INCREMENTAL=0. Identity WARN: app token request got HTTP 403 from the proxy, run acted as owner account.
