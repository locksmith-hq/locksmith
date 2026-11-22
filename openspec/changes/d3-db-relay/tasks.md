# Tasks: D3 Postgres relay

## 1. Bindings and reusable auth [sonnet]
- [x] 1.1 [haiku] Verify pgwire's current version, release date and codec-only use (decision 1); add it pinned to `services/gateway/Cargo.toml` and record the result in design.md "OSS used".
- [x] 1.2 `[[pg]]` binding table in `services/gateway/src/config.rs` (shape in design.md) with validation: unique name and secret, no password field, `tls = "disable"` only with `allow_private_hosts`; fixture TOML in tests.
- [x] 1.3 Make `ls-proxy::db::scram` and `md5_password` public sans-IO helpers without changing M6 behaviour.
- [x] 1.4 Verify: `cargo nextest run -p ls-gateway pg_config` and `cargo nextest run -p ls-proxy db`.

## 2. Listener and agent auth [opus]
- [x] 2.1 `services/gateway/src/pg/listener.rs`: optional TCP listener (`LOCKSMITH_GATEWAY_PG_LISTEN`), tokio-rustls TLS required before startup, GSSENC answered `N`, plaintext startup refused, handshake timeout.
- [x] 2.2 Cleartext password message carries the agent token, verified with `AgentAuth`; fixed SQLSTATE errors (`28P01`, `28000`, `3D000`) built with pgwire; nothing logged but slugs.
- [x] 2.3 Check order binding → relay grant → address guard → decrypt (decision 4); `db.session.denied` ledger event for every refusal after token parse.
- [x] 2.4 Verify: `cargo nextest run -p ls-gateway pg_auth`: plaintext refused, bad token, unbound database, no grant, private host without permission; each asserts no decrypt and no upstream call.

## 3. Upstream auth and relay [opus]
- [x] 3.1 `pg/upstream.rs`: connect with the binding's TLS mode, send the bound user and database plus the allow-listed client parameters only (decision 6), drive SCRAM-SHA-256 and md5 with the decrypted password in `secrecy` types; refuse cleartext unless TLS or loopback.
- [x] 3.2 After upstream `AuthenticationOk`: forward `ParameterStatus` and `ReadyForQuery`, replace `BackendKeyData` with a gateway key, then splice both directions, framing backend messages to redact `E` and `N` text via `ls-redact`.
- [x] 3.3 Cancel map: `CancelRequest` on the listener forwarded to the mapped upstream key; entries removed on session close.
- [x] 3.4 Verify: `cargo nextest run -p ls-gateway pg_relay` against a testcontainers `postgres:18` with SCRAM and with md5: query works, client `user`/`options` ignored, cancel works, cleartext-over-plain refused.

## 4. Redaction, revocation and audit [sonnet]
- [x] 4.1 `db.session.opened` and `db.session.closed` (reason, duration, bytes) ledger events; fail closed (no upstream connect) if the opened event cannot be appended.
- [x] 4.2 Per-session watcher: re-check grant through `GrantCache` and token expiry every TTL; close both legs and record reason `revoked` or `expired`.
- [x] 4.3 Add Postgres cases to `tests/adversarial/gateway/`: password echoed in `RAISE` error and notice, `options` role switch, startup parameter injection, cancel with a guessed key.
- [x] 4.4 Verify: `cargo nextest run -p ls-gateway pg_audit pg_revoke`, `bash tests/adversarial/run.sh`, `just leak-scan`, `just audit-verify`.

## 5. Client setup [sonnet]
- [x] 5.1 `smith db connect <name> --gateway <url> [-- cmd]`: child env `PGHOST`, `PGPORT`, `PGDATABASE=<binding>`, `PGSSLMODE=verify-full` (or `require` with a warning), optional `PGSSLROOTCERT`, `PGPASSWORD` set to the agent token in the child only; nothing written to disk.
- [x] 5.2 `smith doctor` check `db.gateway` (listener reachable over TLS, no `~/.pgpass` entry for bound hosts); CLI and MCP help text.
- [x] 5.3 Verify: `cargo nextest run -p smith-cli db`.

## 6. Console and desktop [sonnet]
- [x] 6.1 Contract (decision 10, D2-1, D2-2): `BindingSummary` (kinds `http`, `git`, `pg`, `aws`; non-secret fields only) and `GET /v1/bindings` in the control-plane OpenAPI (utoipa) and `packages/control-plane-client` (types, client call, `fixtures.ts` entries for every kind); verify `npm test --workspace packages/control-plane-client` and `npm run lint --workspace packages/control-plane-client`.
- [x] 6.2 Gateway publishes its non-secret binding inventory at startup with `PUT /internal/v1/gateway/bindings` (service token, retry like the audit append; a failure is logged and never blocks the relay); the control plane stores the latest snapshot per org and serves `GET /v1/bindings` to org members; tests assert no password, template value or secret material in the stored row or the response (`cargo nextest run -p ls-control-plane bindings` and `cargo nextest run -p ls-gateway bindings_publish`).
- [ ] 6.3 Show bindings (Postgres: name, host, port, user, database, TLS mode; never a password; other kinds with their non-secret fields) on a new Bindings page under Agent Gateway in `apps/web` and `apps/desktop` (decision T3-1 sidebar), built on the 6.1 fixtures then the real client, with Vitest tests.
- [ ] 6.4 Verify: `npm test --workspace apps/web` and `just apps-build`.

## 7. Local verification [sonnet]
- [x] 7.1 `just db-smoke` recipe and `tests/e2e/tests/db_relay.rs`: start gateway and API, create a SCRAM role on the compose Postgres, register an agent, grant, run real `psql` through `smith db connect --gateway`, assert the result, that `db connect` creates or modifies no file holding the token or a password (existing `agent.json` excepted, home snapshotted before and after), and that no file holds a database password.
- [ ] 7.2 `just up`, `just db-smoke`, `just apps-build`, then `just ci`.
