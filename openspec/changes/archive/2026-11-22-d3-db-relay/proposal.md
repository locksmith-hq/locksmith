## Why
Databases are the third surface an agent needs after Git and AWS, and `psql`, ORMs and migration tools speak the Postgres wire protocol, not the JSON relay. Today the only Postgres path is the local daemon relay (M6: `crates/ls-proxy/src/db/postgres.rs`, `smith db connect`), which is synchronous, single-user and gated by the local session tree. The hosted gateway (`services/gateway`) has no TCP listener besides HTTP, so an agent in a hosted org cannot reach a database without holding its password.

## What changes (usable outcome)
An enrolled agent runs `smith db connect <name> --gateway <url> -- psql` (or any libpq client) and gets a working Postgres session against a bound database with **no database password anywhere on the agent host**: not in its environment, `~/.pgpass`, config, history or process list. The gateway runs a TLS pgwire listener, authenticates the agent with its agent token, checks the grant and binding before any decrypt, authenticates upstream with the stored password (SCRAM-SHA-256 preferred), then relays the session. Server error and notice text is redacted, revocation closes open sessions, and each session writes ledger events.

Protection is labelled honestly: the database password is **prevented** from reaching the agent; what the agent can do inside the database is only **contained** by the bound role's own privileges; ledger events give **detection**.

- New gateway module `pg` with its own listener, a `[[pg]]` binding table in the bindings file, and a `db.*` ledger event family.
- `smith db connect --gateway` and a `smith doctor` check; Postgres bindings shown in the web console and desktop app.
- `just db-smoke` against the compose `postgres:18` service.

## Capabilities

### New Capabilities
- `gateway-db-relay`: the hosted gateway's Postgres wire relay: agent authentication, binding and grant checks, upstream authentication with an injected password, redaction, revocation and audit.

### Modified Capabilities
None.

## Out of scope
- MySQL, Redis and other databases (the M6 local relays stay as they are).
- Query inspection, per-statement policy, row filtering or session recording (Access Broker is later direction, decision H1-4; per-statement policy belongs to T2).
- Dynamic or rotated database users (phase 5), client certificate (mTLS) upstream auth, GSSAPI, the replication protocol.
- Cloud (AWS) deployment of the listener and a public Network Load Balancer.

## Depends on
none (builds on the shipped S3 gateway, S4 connector, S5 ledger and the M6 local Postgres relay in `ls-proxy::db`). Nothing in the roadmap lists D3 in `Needs`, so there is no Contract task group.

## Impact
`services/gateway` (new listener and module, config, audit kinds), `crates/ls-proxy::db` (SCRAM and md5 helpers made reusable), `crates/smith-cli` (`db connect --gateway`, doctor), `apps/web`, `apps/desktop`, `tests/e2e`, `tests/adversarial`, `justfile`.
