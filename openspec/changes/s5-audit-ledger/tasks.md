# Tasks: S5 audit ledger

## 1. Chain core extracted from ls-vault [opus]
- [x] 1.1 Create `crates/ls-audit` (pure, no IO): the length-prefixed field encoder, `row_hash`, and a verify walk over rows and checkpoints that returns the first broken `seq` and a tail-truncation result; ledger domain tag `locksmith-ledger-v1`.
- [x] 1.2 Switch `ls-vault` audit to `ls-audit` for encoding and the verify walk, keeping its domain tag, MAC ratchet and on-disk bytes; add a golden-vector test made from the current `ls-vault` output before the switch.
- [x] 1.3 Verify: `cargo nextest run -p ls-audit -p ls-vault` passes, including the golden vectors, proptest round-trips, and the existing vault audit tests unchanged.

## 2. Ledger store and append in the control plane [opus]
- [x] 2.1 Migrations: `audit_heads`, `audit_events` (UUIDv7 `id`, PK `(org_id, seq)`, RLS and FORCE RLS, INSERT and SELECT only for the app role), `audit_checkpoints`, `audit_verify_runs`, an `audit_verifier` role (SELECT and BYPASSRLS, used only by the CLI, plus INSERT on `audit_verify_runs` only, with a policy that allows rows for the org being verified); revoke INSERT on `gateway_audit`. RLS and FORCE RLS on `audit_heads`, `audit_checkpoints` and `audit_verify_runs`; the app role gets INSERT and SELECT only on `audit_checkpoints`, and no UPDATE or DELETE on `audit_checkpoints`, `audit_verify_runs` or `audit_heads` beyond the head update in 2.2.
- [x] 2.2 Postgres store in `ls-audit` (feature `postgres`, sqlx): append in one transaction (set `app.org_id`, lock the head row, hash, insert, update the head); event attributes take an allow-listed identifier type only, never a free-form string from a request.
- [x] 2.3 Control plane appends S4 agent and grant admin events, and serves `POST /internal/v1/audit/events` behind the service token; `openapi.json` updated.
- [x] 2.4 Verify: `cargo nextest run -p ls-audit --features postgres -p ls-control-plane` covers 50 concurrent appends giving seq 1..50 with intact links, app-role UPDATE and DELETE refused on `audit_events`, `audit_checkpoints` and `audit_verify_runs`, RLS on all three new tables, cross-org isolation, a missing service token returning 401, and no canary in any stored event.

## 3. Gateway writes to the ledger [opus]
- [x] 3.1 The gateway sends an `attempt` event before the key unwrap and fails closed with 503 if it fails; it sends an `outcome` event after the upstream call (3 retries); denials append a `denied` event; writes to `gateway_audit` are removed.
- [x] 3.2 Verify: `cargo nextest run -p ls-gateway` covers an allowed call giving `attempt` plus `outcome`, a refused call giving `denied`, an unreachable append endpoint giving 503 with no decrypt call and no upstream request, and no new `gateway_audit` rows.

## 4. Signed checkpoints [opus]
- [x] 4.1 Compose and `openbao-init.sh` create the `audit-checkpoint` Ed25519 transit key and a sign-only policy and token for the control plane; the public key is written to the verifier config by `just up`.
- [x] 4.2 Checkpoint job in the control plane (a `FOR UPDATE SKIP LOCKED` loop, A0-2): every 1000 events or 60 s per org with new events, sign the checkpoint bytes through OpenBao and store it in `audit_checkpoints`. The bytes are defined in `ls-audit`: a length-prefixed encoding of `(org, seq, head hash, time)` under its own domain tag `locksmith-checkpoint-v1`, pinned by a golden vector shared with the offline verifier.
- [x] 4.3 Verify: `cargo nextest run -p ls-control-plane` covers a checkpoint created at the threshold, a signature that verifies with `ed25519-dalek` under the published key, and a signature that fails under another key.

## 5. Verify and export CLI [opus]
- [x] 5.1 `locksmith-audit verify --db` (verifier role) and `--dir` (offline, public key only), with `--json` output; results are recorded in `audit_verify_runs`; it exits non-zero with the org and first broken seq.
- [x] 5.2 `locksmith-audit export` to the file sink (JSON Lines per org, checkpoints, cursor, temp file plus rename plus fsync) behind an `AuditSink` trait; incremental, never writes an event twice.
- [x] 5.3 `just audit-verify` (runs `verify --db --checkpoints-from` the export directory), `just audit-export`, and `just audit-tamper-test`; the tamper test runs as the owner role: edit a field, delete a row, swap two seqs, truncate past a checkpoint, edit an exported line, and the strongest case: rewrite one event, recompute every later hash, and delete the `audit_checkpoints` rows. Each must fail verify, the last with the export's checkpoints present; the untouched ledger must pass.
- [x] 5.4 Verify: `cargo nextest run -p ls-audit` and `just up && just audit-tamper-test`.

## 6. API, console and desktop [sonnet]
- [x] 6.1 `GET /v1/audit/events` (paged, newest first, org-scoped) and `GET /v1/audit/status` (latest checkpoint, latest verify run); `openapi.json` and the generated TS types updated.
- [x] 6.2 Web console audit page: an event list with kind, actor, target and outcome, plus chain status (latest checkpoint seq, verify result and time).
- [x] 6.3 `apps/desktop` audit view reading the same API through the Tauri frontend.
- [x] 6.4 Verify: `cargo nextest run -p ls-control-plane` (API and RLS), `npm run lint`, and `just apps-build`.

## 7. Smoke and e2e [sonnet]
- [x] 7.1 `just audit-smoke`: register an agent, grant the canary, relay through `smith`, wait for a checkpoint, export, `audit-verify --db` and `--dir`, then `just leak-scan` over the DB, Loki, Tempo and the export directory; record append p99 at 200 relays/s with `oha` in progress.md.
- [x] 7.2 Verify: `just up && just audit-smoke && just leak-scan`.

## 8. Local verification
- [ ] 8.1 `just up`, `just audit-smoke`, `just audit-tamper-test`, `just apps-build`, then `just ci`.
