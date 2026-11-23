# Design: D3 Postgres relay

## Context
- See proposal.md (Why). Shipped: the M6 local relay in `crates/ls-proxy/src/db/` (`postgres.rs` handshake and splice, `scram.rs` SCRAM-SHA-256 client, md5, TLS modes, redacted `ErrorResponse`/`NoticeResponse`). It is synchronous (one thread per direction) and gated by the local session tree, so it cannot serve a hosted gateway as is.
- The hosted gateway (`services/gateway`, crate `ls-gateway`) is tokio + axum and serves HTTP only. Reusable pieces: agent token verification (`auth.rs`), `GrantCache` and the relay-mode check (`grants.rs`), `Decryptor` (`decrypt.rs`), the address guard (`egress::address_allowed`), `ls-redact`, and the ledger sink (`audit.rs`). Bindings are a TOML file with `deny_unknown_fields` (`config.rs`).
- Agents hold only an agent token (S4). As in D1, the agent token is the credential the client presents; the database password never leaves the gateway.

## Goals / Non-Goals
**Goals:** a TLS pgwire listener in the gateway; agent-token auth; `[[pg]]` bindings; upstream SCRAM/md5 with the stored password; streamed relay with server-message redaction; cancel requests; revocation closing open sessions; `db.*` ledger events; `smith db connect --gateway`.
**Non-Goals:** query parsing or policy, connection pooling across agents, MySQL/Redis, mTLS upstream, cloud deployment (see proposal Out of scope).

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **Use `pgwire` for message framing and the client-side handshake** (SSLRequest, StartupMessage, password message, `ErrorResponse`, `BackendKeyData`), and splice the post-auth stream on `tokio` with frame-level inspection of backend `E`/`N` messages only. | Port the M6 sync relay into `spawn_blocking` threads (two OS threads per session, no async cancellation); `postgres-protocol` (client-side serialisers only, no frontend parser for a server); hand-written codec (new protocol code touching secrets). | `docs/research/oss-building-blocks.md` row "Postgres relay: pgwire"; Postgres protocol flow docs (postgresql.org/docs/18/protocol-flow.html); M6 relay already proves the splice-and-redact shape. |
| 2 | **Dedicated TCP listener** (`LOCKSMITH_GATEWAY_PG_LISTEN`, default off) with **TLS required** before startup (tokio-rustls, the gateway's existing rustls `ring` provider). GSSENCRequest answered `N`; plaintext startup refused. | Tunnel pgwire inside HTTP/WebSocket (libpq cannot speak it, needs a local shim); allow plaintext on loopback (token on the wire in clear). | libpq `sslmode` docs (postgresql.org/docs/18/libpq-ssl.html); AGENTS.md security rules. |
| 3 | **Agent token as the cleartext password over TLS**; startup `database` = binding name; startup `user` ignored for routing. The server requests `AuthenticationCleartextPassword` only after TLS. | SCRAM with the agent token (the gateway would need the token's plaintext anyway; no gain); client certificates (needs per-agent PKI, not in S4). | Same pattern as D1's credential helper (agent token is the presented credential); Postgres `password` auth over TLS is standard (pg_hba `password` method docs). |
| 4 | **Check order:** TLS → token → binding exists → grant (relay mode) → address guard → decrypt → upstream connect. Every refusal before decrypt is a Postgres `ErrorResponse` with a fixed SQLSTATE and message. | Decrypt first and check later (wastes KMS calls, widens exposure). | S3/D1 rule: refuse before any fetch or unwrap. |
| 5 | **Reuse M6 SCRAM and md5** by exposing `ls-proxy::db::scram` and `md5_password` as public, sans-IO helpers; the gateway drives them over async IO. Cleartext upstream only over TLS or loopback. | Rewriting SCRAM in the gateway; `tokio-postgres` as the upstream (it owns the session and cannot hand back a raw stream to splice). | `crates/ls-proxy/src/db/scram.rs` already tested against Postgres; RFC 7677. |
| 6 | **Client startup parameters are not forwarded** except a fixed allow-list (`application_name`, `client_encoding`, `DateStyle`, `TimeZone`, `extra_float_digits`); upstream `user` and `database` come from the binding. | Forward everything (`options=-c role=...` would change the session role). | Postgres startup parameters doc; M6 relay behaviour. |
| 7 | **Gateway-issued `BackendKeyData`** (random pid/secret) mapped in memory to the upstream key; `CancelRequest` on the listener is forwarded to the mapped upstream. | Pass the upstream key through (leaks upstream identifiers, lets a client cancel other sessions on the same server). | Postgres protocol "Canceling Requests" section. |
| 8 | **Per-session revocation watcher** re-checks the grant through `GrantCache` every TTL and checks token expiry; on loss it closes both legs. | Check only at connect (a revoked grant would keep a session alive for hours). | S4 design decision 4 (`MAX_GRANT_TTL`). |
| 9 | **Ledger events** `db.session.opened`, `db.session.closed` (reason, duration, bytes in/out), `db.session.denied` (slug). No query text. | Query logging (Access Broker direction, H1-4; would put data in the ledger). | S5 ledger schema; decision H1-4. |
| 10 | **Bindings page data source** (D2-1, D2-2; rescue #610): the gateway, which owns the bindings file, pushes a non-secret inventory (kind, name, and per kind: HTTP origin and header name; git repo; Postgres host, port, user, database, TLS mode; AWS role, region, `vend`, max duration) to the control plane with `PUT /internal/v1/gateway/bindings` at startup, using the existing service token. The control plane keeps the latest snapshot per org and serves `GET /v1/bindings` to org members; the console and desktop read only that. Never a password, template value, secret id material or key. | Console calls the gateway directly (humans have no gateway credential; adds CORS and a second auth path); bindings move into the control-plane database now (a larger data-model change that belongs with T2's per-binding usage modes). | `services/gateway/src/audit.rs` already appends through `/internal/v1/audit/events` with the service token; `services/control-plane/src/api/internal.rs` hosts the internal routes. |

## Binding shape
```toml
[[pg]]
name = "app"                 # the client's `database` startup parameter
secret_id = "<uuid>"         # the password secret
host = "postgres"            # fixed upstream host
port = 5432
user = "app_rw"
database = "app"
tls = "require"              # require | verify-full | disable (disable only with allow_private_hosts)
allow_private_hosts = false
```
Validation: unique `name` and `secret_id` across all bindings, no password field, `tls = "disable"` rejected unless `allow_private_hosts`.

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| pgwire | Apache-2.0 | 0.42.3 | 2026-11-13 | message codec and server handshake | not AGPL |
| tokio-rustls | MIT/Apache-2.0 | 0.26.x (in Cargo.lock) | n/a | TLS on the listener and upstream | not AGPL |
| rustls (workspace) | MIT/Apache-2.0/ISC | 0.23.46 | n/a | TLS, `ring` provider | not AGPL |
| rcgen (dev only) | MIT/Apache-2.0 | 0.14.x (in Cargo.lock) | n/a | test listener certificates | not AGPL |
| testcontainers (dev, workspace) | MIT/Apache-2.0 | 0.28 | n/a | `postgres:18` upstream in tests | not AGPL |
| tokio-postgres (dev only) | MIT/Apache-2.0 | 0.7.x (in Cargo.lock) | n/a | test client through the gateway | not AGPL |

**[verified 2026-11-20]** pgwire 0.42.3 (crates.io, released 2026-11-13, MIT/Apache-2.0) is the latest stable; pinned `=0.42.3` with `default-features = false` in `services/gateway/Cargo.toml`, so only the message codec is pulled and the query-handler server loop (server-api features) is not enabled. Built in-house: only the relay glue (check order, parameter allow-list, cancel map, redaction hook). A maintained Rust Postgres proxy with injected credentials was searched for first (pgcat and pgdog: poolers that read static passwords from their config, no per-session decrypt hook; supavisor: Elixir), none fits a gateway that decrypts per session.

## How an agent debugs this
`just up` (compose `postgres:18`), `just api`, `just gateway` with `LOCKSMITH_GATEWAY_PG_LISTEN` set; `just db-smoke` runs psql through the gateway. Ledger: `GET /v1/audit/events` (`db.session.*`), `just audit-verify`; `just leak-scan` for canaries; gateway spans (`pg.session`, `pg.upstream_auth`) in Tempo and logs in Loki via the Grafana MCP; upstream sessions in `pg_stat_activity` through the Postgres MCP; `smith doctor` check `db.gateway`.

## Risks / Trade-offs
- Long-lived sessions outlive a grant until the next watcher tick: bounded by the grant cache TTL and tested.
- The agent token is in the child process environment (`PGPASSWORD`) for the session: it is the agent's own short-lived identity, not the database password; labelled containment.
- A bound role with broad privileges lets the agent read or change data: the binding docs say to bind a least-privilege role; containment only.
- pgwire API churn (0.x): pinned exact version, codec use kept behind one module.
