# Tasks

## 1. HTTP relay

- [x] 1.1 Opaque token issue/list/revoke and binding storage, plus redactor label registration. Verify: unit tests and `smith token ls --json` with no values.
- [x] 1.2 Host-forwarding relay with swap rules, allowlist and audit (design D2). Verify: integration tests against a local echo server for allowed, wrong-host 403 and wrong-placement cases.
- [x] 1.3 Response cleansing including gzip, br and zstd (design D3). Verify: a test where the echo server reflects the key compressed and the client gets it masked.
- [ ] 1.4 Provider catalog for the top 30 APIs and its `smith run` integration (env holds the opaque token plus the base URL). Verify: live smoke tests for Stripe test mode and OpenAI with test keys (manual workflow).
  - Built: catalog (32 providers), `smith run` integration with an e2e test against a local echo upstream, and `.github/workflows/http-live-smoke.yml`. The live workflow needs repository secrets and has not been run, so this stays open.
- [x] 1.5 Local CA mode with name constraints, install and uninstall (design D4). Verify: a test where `curl --cacert` succeeds for an enabled host and fails for `example.org`.

## 2. DB relay

- [x] 2.1 Postgres relay (startup, SCRAM upstream, splice). Verify: e2e against a Postgres container with `psql` and `sqlx migrate run`.
- [x] 2.2 MySQL and Redis relays. Verify: e2e against containers.
- [x] 2.3 Session binding and revoke-closes-connections. Verify: e2e where a `pg_sleep(30)` connection is closed within 1 s of revoke.

## 3. Diagnostics and adversarial

- [x] 3.1 Doctor checks `http.relay`, `http.ca_constraints`, `db.relay.*`. Verify: snapshots.
  - Done: `doctor_m6_snapshots` (smith-cli `tests/http.rs`) compares `smith --json doctor` with `tests/fixtures/doctor_m6/{offline,daemon_locked,session_ca}.json` and checks every id against the schema pattern, which now allows `-` (`db.relay.prod-ro`).
- [x] 3.2 **Gate A3** (DB) and A3b (HTTP reflection, wrong-host, header echo), scripted. Verify: `run.sh A3 A3b` gives zero hits.
  - Done: `run.sh A3 A3b` (and `run.sh all`) passes as root and as an unprivileged user; the oracle finds no canary. The first runs found three leaks, now fixed with regression tests (design D8): the DB password sent in cleartext to a fake server named by an edited binding, the API key sent to a host named by `--host` or an edited binding, and a gzip transfer-coded reflection passed through undecoded.
- [ ] 3.3 **Gate A3/A3b** live: Claude Code inside the scoped session is told to extract the DB password and the API key by any means. Verify: `run.sh A3 A3b --agent claude` gives zero hits.
  - Built: both cases run `claude -p` with an attack prompt when `LIVE_AGENT=claude` (nightly `adversarial.yml`). Not run yet: it needs the `ANTHROPIC_API_KEY` repo secret.
