# Proposal: M6 HTTP and Database Relays

## Why

After Git, the next most common credentials are SaaS API keys (Stripe, OpenAI, Twilio…) and
database passwords. v5 §6.1.3 and §6.2 describe a loopback relay for each. M6 builds them on the
M5 forwarder, so code an agent writes or runs can call those APIs and databases without holding
the keys.

## What Changes

- **Opaque tokens:** `smith token issue STRIPE_KEY` returns `lsk_<random>` and binds it to
  `{secret, upstream host allowlist, header/query placement, lease}`. Projects can expose opaque
  tokens via `smith run` (Mode B+C hybrid: the env var holds the opaque token, not the secret).
- **Host-forwarding HTTP relay (preferred, no TLS interception):** `http://127.0.0.1:<port>/h/<host>/…`.
  Apps set their SDK base URL (e.g. `STRIPE_API_BASE`, `OPENAI_BASE_URL`). The relay validates and
  swaps the opaque token for the real one, then forwards over TLS. Response bodies and headers are
  redacted.
- **Explicit-proxy mode with a local CA (opt-in):** `HTTPS_PROXY=http://127.0.0.1:<port>`. A per-install
  CA, name-constrained to the allowlisted hosts, is added to the trust store only on
  `smith http ca install`. Pinned clients are documented as unsupported.
- **Database relay:** a local Postgres, MySQL or Redis listener. The client connects without a
  password. The relay authenticates upstream with the vault password or mTLS cert, then proxies the
  bytes. TLS is used upstream.
- Built-in provider catalog (`providers.toml`): base-URL env names and auth placement for the 30
  most common APIs.
- Doctor checks: `http.relay`, `http.ca_constraints`, `db.relay.<name>`.

## Usable outcome

`smith run -- npm run dev` gives the app `STRIPE_KEY=lsk_…` and `STRIPE_API_BASE=http://127.0.0.1:…`.
API calls work, and a printed key is useless anywhere else. `smith db connect prod-ro` gives `psql`
a password-less local endpoint, and migrations work.

## Capabilities

### New Capabilities
- `http-delegation`: Opaque tokens and HTTP relays that attach real API credentials upstream.
- `db-relay`: Password-less local database endpoints that authenticate upstream.

### Modified Capabilities

## Out of scope

- WebSocket and gRPC auth injection (the backlog has gRPC metadata injection).
- Query-level DB policy such as "read-only" enforcement by SQL parsing. v6 uses separate DB users
  per environment instead.

## Impact

`ls-proxy` grows the http and db modules, plus the `rcgen` crate for the local CA. Free tier is
limited to 2 HTTP upstreams and has no DB relay, enforced in M13.
