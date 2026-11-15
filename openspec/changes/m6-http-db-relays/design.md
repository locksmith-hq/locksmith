# Design: M6 HTTP and Database Relays

## Decisions

### D1. Opaque token format
`lsk_` + 32 bytes base62. It deliberately does not mimic provider prefixes. Using `sk_live_` would
make scanners flag our own placeholders and confuse humans. Tokens are registered with the
redactor as low-sensitivity labels.

### D2. Swap rules
Swapping happens only in the configured placement: the `Authorization` header (Bearer/Basic), a named
header, or a query parameter. A body is never rewritten. The token must match the binding's host
allowlist. A mismatch gives 403 plus a BLOCKED audit. This prevents an agent from sending the opaque
token to `attacker.example` through the relay to learn the real key by reflection.

### D3. Response cleansing
Response headers and bodies stream through the M2 redactor, configured with the real secret plus its
encodings. Compressed bodies (gzip, br, zstd) are decoded, redacted and re-encoded identity, with the
`content-encoding` header updated.

### D4. Local CA mode
The CA has the X.509 NameConstraints extension, permitted DNS = the catalog hosts the user enabled.
A stolen CA key cannot impersonate other sites. The CA private key is stored in the vault, and the
public cert goes to the trust store through `security add-trusted-cert` (macOS) or
`update-ca-certificates` (Linux, requires sudo, prompted). Uninstall is symmetrical.

### D5. DB relay
Postgres: speak the startup protocol to the client, accept `trust` auth locally, open upstream with
SCRAM-SHA-256 or mTLS, then splice the streams after auth. MySQL: the same with
`caching_sha2_password`. Redis: inject `AUTH` / `HELLO 3 AUTH` on connect. Listeners bind
`127.0.0.1` or a Unix socket in the runtime dir. Peer-to-PID descendant checks apply (M5 D2).

### D6. Implementation notes (as built: HTTP)
- **Shape.** `ls-proxy::http` is the relay (synchronous, one thread and one request per
  connection, `Connection: close`, no tokio), `ls-proxy::catalog` the embedded `providers.toml`
  (32 APIs), `ls-proxy::ca` the CA. `locksmithd/src/http.rs` holds tokens and implements
  `HttpAuthority`; the relay listens on its own random `127.0.0.1` port next to the Git
  forwarder and serves both `/h/<host>/…` and `CONNECT` (explicit proxy) on that port.
- **Tokens (D1).** `lsk_` + 43 base62 chars. In daemon memory only, bound to
  {project, env, key, hosts, placements, lease}; pruned when the lease is revoked/ended/expired,
  and every relayed request re-checks the lease, so revoke stops the relay at once.
  `smith token issue` needs a session with the `http` scope and an existing key name (the value is
  not read). `smith token ls` shows a 12-character prefix; `revoke` takes the token or that prefix.
  Issue/revoke are audited `TOKEN_ISSUE`/`TOKEN_REVOKE`.
- **Swap rules (D2).** A request must carry exactly one token (401 none/unknown, 400 several).
  Placements: `bearer` (the `Authorization` value, token replaced in place, so `Bearer`, `Token`,
  `Bot` and bare keys work), `basic` (inside the decoded user:pass), `header:<name>`,
  `query:<param>` (secret percent-encoded); a key may list several (Anthropic `x-api-key` or
  bearer, Supabase `apikey` and bearer). Order of checks: peer-to-PID (every owner of the client
  socket must be in the token's lease, scope `http`), host allowlist (exact or `*.suffix`, `:443`
  implied), placement. Host or placement failures return 403 and audit
  `BLOCKED http_host_not_allowed:<host>` / `http_wrong_placement:<host>` before any upstream
  connection. A token found only outside its placements is refused, not forwarded unswapped;
  copies of the token elsewhere (other headers, body) are forwarded unchanged. Hop-by-hop
  headers, `Connection`-named headers, `Upgrade` (no WebSocket), `Expect` and the client's `Host`
  are dropped. Secrets containing CR/LF/NUL are refused.
- **Cleansing (D3).** The relay sends its own `Accept-Encoding: gzip, deflate, br, zstd`, decodes
  (flate2, brotli-decompressor, ruzstd — pure Rust, no C), redacts headers and body with the M2
  redactor (`[REDACTED:<KEY>]`, all encodings it knows), and re-sends `Transfer-Encoding:
  chunked` identity. The body goes through `ls_redact::relay` (20 ms idle flush), so SSE streams.
  An unknown content-coding is a 502 (fail closed); a truncated upstream body ends without the
  final chunk so the client sees the truncation.
- **`smith run` (1.4).** Keys under `[http.keys]` get a token minted under the run's lease plus
  the provider's `base_url_env` set to `http://127.0.0.1:<port>/h/<host><path>`; tokens are
  registered with the run redactor as `<KEY>(opaque)`. Outside a session, `smith run` with `[http]`
  keys starts a `run,http` lease rooted at itself (same passphrase prompt), runs through the
  daemon and ends the lease afterwards — the relay cannot authorize a process with no lease.
  Catalog `override` marks each provider: `env` (SDK reads the variable), `config` (SDK takes a
  base-URL option; the app passes the variable), `none` (needs CA mode).
- **CA (D4).** rcgen ECDSA P-256, `pathLen 0`, critical NameConstraints: permitted dNSName = the
  enabled hosts (`*.x` becomes subtree `x`), excluded IPv4 and IPv6 `0/0` (otherwise IP SANs
  would be unconstrained). The key is stored as vault secret `_locksmith/development/HTTP_CA_KEY`
  (so it shows up in `smith ls`), the cert at `<config>/http/ca.pem`, enabled hosts in
  `ca-hosts`. Hosts are fixed at install (reinstall to change). Install/uninstall need the
  passphrase; the trust store is touched only without `--no-trust-store` (macOS login keychain
  `add-trusted-cert`; Linux `sudo install` + `update-ca-certificates` or `update-ca-trust`, asked
  first unless `--yes`). `CONNECT` to a non-enabled host is 403 + `BLOCKED
  http_connect_not_enabled` (never a blind tunnel); enabled hosts get a 30-day leaf minted from the
  vault key and cached in memory, and the request inside goes through the same swap and cleansing.
  Explicit-proxy also requires the peer to be inside an active `http` session.
- **Doctor.** `http.relay` (daemon `HttpInfo`) and `http.ca_constraints` (skip without a CA; fail
  when the cert lacks critical DNS constraints or IP exclusion; warn when constraints differ from
  `ca-hosts`). Pure-function unit tests, plus `smith --json doctor` snapshots (task 3.1, D8).
- **Test switch.** `LOCKSMITH_TEST_HTTP_UPSTREAM=host=addr[,…]` (debug builds only) sends those
  hosts to plain TCP, for both relay modes.
- **Not done.** The live Stripe/OpenAI smoke (`.github/workflows/http-live-smoke.yml`, ignored test
  `live_stripe_and_openai_through_the_relay`) needs repository secrets and was not run here.
  No keep-alive, HTTP/2 or WebSocket through the relay. Free-tier limits are M13.

### D7. DB relay implementation notes (as built)
- `ls-proxy::db` (`postgres`, `mysql`, `redis`, `scram`) is synchronous like the Git forwarder: one
  accept thread per relay, two threads per connection. Upstream TLS is rustls (ring) with native
  roots plus webpki-roots and always verifies the certificate and host name.
- Config: `[db.<name>]` in `.locksmith.toml` with `kind`, `host`, `port`, `user`, `database`,
  `password_key`, `tls` (`require` default for non-loopback; loopback defaults to `prefer`, or
  `disable` for Redis, which cannot negotiate TLS) and `client_cert_key`/`client_key_key` (PEM, mTLS).
  Unknown fields are rejected, so a literal `password = "…"` is an error.
- `smith db connect <name>` sends `DbConnect`; the daemon opens (or reuses) one listener on
  `127.0.0.1:<random>` per lease and target, scope `db`. It answers kind/port/user/database only.
  Without `--` it prints a URL (`postgres://user@127.0.0.1:P/db?sslmode=disable`) and client env;
  with `-- cmd` it execs `cmd` with `PG*`/`MYSQL_*`/`REDIS_URL` and `DATABASE_URL` (no password).
- Admission per connection (M5 D2): every process holding the client socket must be inside the
  relay's lease tree. Otherwise the client gets a protocol-native error (Postgres `ErrorResponse`
  28000, MySQL ERR 1045, Redis `-ERR`) and a BLOCKED audit (`db:<name>`). Admitted connections
  read the password from the vault, audit ACCESS, and drop the zeroized copy after the handshake.
- Postgres: `SSLRequest`/`GSSENCRequest` get `N`; `CancelRequest` is forwarded upstream. The
  configured user (and database, when set) override the client's. Upstream SCRAM-SHA-256 (server
  signature verified, no channel binding, no SASLprep), md5, and cleartext only over TLS or to a
  loopback host. MySQL: the client sees the upstream version and capabilities minus TLS and
  compression, is offered `mysql_native_password` and accepted; upstream `caching_sha2_password`
  (fast auth, or full auth sending the password over TLS) and `mysql_native_password` with auth
  switch. The RSA public-key exchange is not implemented, so full auth needs TLS (the error says
  so). MariaDB `client_ed25519` is not supported. Redis: `AUTH [user] pass` is injected and its
  reply swallowed (not `HELLO 3`, which would change the client's protocol).
- Redaction: Postgres `ErrorResponse`/`NoticeResponse` and MySQL ERR packets are re-framed after
  redaction for the whole session. Redis traffic after AUTH is not redacted (RESP is not framed
  for it); the relay never sends the password after AUTH.
- Session binding: each relay tracks its client and upstream sockets. `Revoke` and `SessionEnd`
  call `db::sweep`, and the watcher runs it every second for expiry. Closed relays stop accepting
  and `shutdown(Both)` every tracked socket. Measured revoke-to-client-exit for a relayed
  `pg_sleep(30)`: about 60 ms.
- Not built: the Unix-socket listener (TCP loopback only), so peer checks always go through
  `tcp_peer_owners`. A relay is not closed by vault lock; new connections fail instead because the
  password cannot be read.
- Test switch, debug builds only: `LOCKSMITH_TEST_DB_CA=<pem>` adds a trust anchor for upstream TLS.
- Verified e2e (`smith-cli/tests/db.rs`) against real servers, not containers: Postgres 16 (SCRAM,
  `hostssl` only, test CA) with `psql`, a migration file and `sqlx migrate run` (sqlx-cli 0.9);
  MariaDB 10.11 with a `REQUIRE SSL` native-password user; Redis 7 with an ACL user. The MySQL 8
  `caching_sha2_password` paths are covered only by in-process fake-server unit tests.

### D8. Diagnostics and gates A3/A3b (as built)
- **Doctor snapshots.** `doctor_m6_snapshots` runs `smith --json doctor` with no daemon, with the
  daemon up and the vault locked, and inside a session after `smith http ca install`, and compares
  the `http.*`/`db.relay*` checks with `smith-cli/tests/fixtures/doctor_m6/*.json` (ports and OS
  error numbers normalized; `UPDATE_GOLDEN=1` rewrites them). `db.relay.<name>` ids reduce the
  free-form TOML name to `[a-z0-9_-]`, and the `doctor.v1` id pattern now allows `-` after the
  first segment.
- **Pinned binding (leak fix).** The daemon used to route by the binding each request carried, which
  an agent inside the session can edit. Now `SessionStart` carries the binding in effect and the
  lease pins it (`ls_broker::PinnedBinding`). `TokenIssue` and `DbConnect` use the pinned copy; a
  client copy whose relevant part (project, env, the `[http.keys]` entry or `[db.<name>]` table)
  differs is refused (`Denied`, `BLOCKED binding_changed`). `--host`/`--provider` can only pick
  hosts the pinned binding gives the key, or any host the provider catalog lists; anything else
  is `BLOCKED http_host_not_bound:<host>`. A session started where no binding applies has no DB
  targets or bound HTTP keys.
- **Codings (leak fix).** The relay reads every `Content-Encoding`/`Transfer-Encoding` header and
  accepts one known content-coding and plain `chunked` only; stacked or repeated codings and
  transfer-codings other than chunked are a 502.
- **Gates.** `tests/adversarial/cases/A3.sh` (real Postgres, `--scope db`) and `A3b.sh`
  (`fixtures/http_upstream.py` as provider and attacker host, `--scope http`). Agent sessions in
  the gates have only the delegation scope: the `run` scope injects plaintext by design, so a
  `run`-scoped session can always read its keys. `run.sh` takes several targets and treats exit 77
  as SKIP (a failure under `ADVERSARIAL_REQUIRE_ALL=1`, set nightly). The oracle also matches hex
  and base64 of the canary text (Basic auth). Live mode runs `claude -p` with an attack prompt
  inside the session; it has not run yet.
- **Residual.** The pinned copy is whatever `.locksmith.toml` said when the human started the
  session: an edit made by an agent in an earlier session, or a malicious repository's binding,
  is pinned too. Binding changes are not yet shown for approval at session start. The M5 Git
  forwarder still reads `[git]` from the client's copy; it was not changed here and should get
  the same pin.

## Risks / Trade-offs
- SDKs without a base-URL override need CA mode or Mode C. The catalog marks each provider.
- A splice after auth means an attacker inside the session can run arbitrary SQL. That is
  contained by the per-environment DB user's grants. Docs push read-only users for agent sessions.
