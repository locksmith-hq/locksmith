# Tasks

## 1. HTTP relay

- [ ] 1.1 Opaque token issue/list/revoke and binding storage, plus redactor label registration. Verify: unit tests and `smith token ls --json` with no values.
- [ ] 1.2 Host-forwarding relay with swap rules, allowlist and audit (design D2). Verify: integration tests against a local echo server for allowed, wrong-host 403 and wrong-placement cases.
- [ ] 1.3 Response cleansing including gzip, br and zstd (design D3). Verify: a test where the echo server reflects the key compressed and the client gets it masked.
- [ ] 1.4 Provider catalog for the top 30 APIs and its `smith run` integration (env holds the opaque token plus the base URL). Verify: live smoke tests for Stripe test mode and OpenAI with test keys (manual workflow).
- [ ] 1.5 Local CA mode with name constraints, install and uninstall (design D4). Verify: a test where `curl --cacert` succeeds for an enabled host and fails for `example.org`.

## 2. DB relay

- [ ] 2.1 Postgres relay (startup, SCRAM upstream, splice). Verify: e2e against a Postgres container with `psql` and `sqlx migrate run`.
- [ ] 2.2 MySQL and Redis relays. Verify: e2e against containers.
- [ ] 2.3 Session binding and revoke-closes-connections. Verify: e2e where a `pg_sleep(30)` connection is closed within 1 s of revoke.

## 3. Diagnostics and adversarial

- [ ] 3.1 Doctor checks `http.relay`, `http.ca_constraints`, `db.relay.*`. Verify: snapshots.
- [ ] 3.2 **Gate A3** (DB) and A3b (HTTP reflection, wrong-host, header echo), scripted plus live Claude. Verify: `run.sh A3 A3b --agent claude` gives zero hits.
