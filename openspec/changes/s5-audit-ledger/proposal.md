# Proposal: S5 audit ledger

## Why
After S4 an agent can use a credential through the gateway, and each relay leaves a row in `gateway_audit`. That table is append-only by grant, but the database owner (or anyone holding that role) can still edit, delete or reorder rows and nobody would notice. S5 makes every audit event part of a per-org hash chain with signed checkpoints, gives operators `just audit-verify` to prove the history is intact, and exports it to a file sink outside the database. A0-11 already decided that the chain lives in Postgres.

## What Changes
- **Audit ledger in Postgres:** an `audit_events` table (org-scoped, RLS, INSERT-only for the app roles) where each event stores `seq`, `prev_hash` and `hash` over a deterministic encoding, plus an `audit_heads` row per org that is locked while each append runs so the chain has no gaps or forks.
- **Shared chain crate `ls-audit`:** the field encoding, row hash and verify walk move out of `ls-vault` into a pure library (no IO). `ls-vault` keeps its exact on-disk bytes, and a golden-vector test proves it. A Postgres store (`sqlx`) sits behind a feature flag.
- **Writers:** the control plane appends agent and grant admin events (S4) directly. The gateway appends relay events through a new internal control-plane endpoint, behind the S3 service token. It records an `attempt` event before it unwraps a key and fails closed if that append fails, then records an `outcome` event afterwards. New writes stop going to `gateway_audit`, which stays read-only as a legacy table.
- **Signed checkpoints:** every 1000 events or 60 s per org (both configurable), the control plane signs `(org, seq, head hash, time)` with an Ed25519 key in OpenBao transit (the KMS stand-in, A0-14) and stores the checkpoint.
- **Export to a file sink:** `locksmith-audit export` writes each org's events as JSON Lines plus the checkpoints to a directory and resumes from a cursor. The sink sits behind an `AuditSink` trait so the S3 Object Lock sink (A0-11) can plug in later.
- **Verify:** `locksmith-audit verify` (and `just audit-verify`) checks the database, or an exported directory, for seq gaps, broken links, edited rows, bad checkpoint signatures and tail truncation behind the last checkpoint. It exits non-zero and reports the first broken `seq`.
- **API and apps:** `GET /v1/audit/events` (paged, org-scoped) and `GET /v1/audit/status` (last checkpoint, last verify result). A web console page and a desktop view list the events and show the chain status.
- **Tamper test:** `just audit-tamper-test` edits, deletes, reorders and truncates rows as the DB owner role and asserts that verify catches each one.

## Capabilities
### New Capabilities
- `audit-ledger`: an append-only, hash-chained, checkpointed audit history per org, with verification and export.

### Modified Capabilities
- `gateway-http-relay` (from S3 and S4): relay audit records go to the ledger, and a relay fails closed when its attempt event cannot be recorded.

## Out of scope
- An S3 Object Lock sink and the Object Lock retention setup (P1, A0-11 and A0-16). Locally the moto stand-in comes with that sink.
- Streaming to a SIEM, Vector or a webhook (later, through the same `AuditSink` trait).
- A public transparency log or witness (Tessera is the upgrade path).
- Audit for human sign-in (T1) and policy decisions (T2). Those changes add their own event kinds.
- Retention, deletion or GDPR erasure of audit events.
- Changes to the local vault audit (`ls-vault` behaviour is unchanged; only its code moves).
- The adversarial suite (S6).

## Depends on
`s4-agent-connector` (agent ids and grant events, gateway token flow).

## Impact
`crates/ls-audit` (new), `crates/ls-vault` (uses `ls-audit`), `services/control-plane` (migrations, internal append endpoint, checkpoint job, audit API, `openapi.json`), `services/gateway` (audit writer), `apps/web`, `apps/desktop`, `infra/compose` (OpenBao transit signing key), `justfile` (`audit-verify`, `audit-export`, `audit-tamper-test`), `tests/e2e`.
