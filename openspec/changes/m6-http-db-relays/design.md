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

## Risks / Trade-offs
- SDKs without a base-URL override need CA mode or Mode C. The catalog marks each provider.
- A splice after auth means an attacker inside the session can run arbitrary SQL. That is
  contained by the per-environment DB user's grants. Docs push read-only users for agent sessions.
