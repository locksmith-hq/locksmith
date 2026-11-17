# Design: S3 gateway HTTP relay

## Context
- S2 (archived) gives `ls-envelope` (`open_version`, `KeyWrapper`, `OpenBaoTransit`), `secret_versions` and the OpenBao split: the control plane token can only `encrypt`; a gateway token can `decrypt`.
- `ls-redact` has `Redactor` with multi-encoding matching and a streaming `relay`. `ls-proxy` has the network guard, catalog and a synchronous forwarder built for the desktop daemon.
- F0 compose has a mock upstream API and the OTel stack; F1 has `just leak-scan`.
- Binding decisions: A0-7, A0-10, A0-14.

## Goals / Non-Goals
**Goals:** the first end-to-end proof that a secret is used without the caller holding it; a gateway that later changes (S4 identity, T2 policy, S5 audit) plug into without rewrites.
**Non-Goals:** MITM or CONNECT proxying, non-HTTP protocols, per-agent grants, hash-chained audit.

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **New axum service `services/gateway`** exposing an explicit relay API (`POST /v1/relay`). Reuse `ls-redact` and the `ls-proxy` network guard as libraries. | Extending the sync `ls-proxy` forwarder (thread per connection, built around a local daemon `Authority`; the service needs async and OTel); `hudsucker` MITM (a relay API needs no CA trust on the caller; MITM is for later explicit-proxy mode) | roadmap S3 spike line; `docs/research/oss-building-blocks.md` row "MITM / injection proxy"; `crates/ls-proxy/src/lib.rs` |
| 2 | **Gateway fetches ciphertext from the control plane** through an internal material endpoint (ciphertext, wrapped DEK, key id) behind a service token. Gateway never reads the control-plane database. | Gateway reading Postgres directly (couples schemas, widens DB credentials); control plane streaming plaintext (it cannot decrypt, S2) | S2 decision 4; A0-4 |
| 3 | **Decrypt path:** unwrap DEK via `OpenBaoTransit` with the gateway token, `open_version`, hold the value in `SecretBytes`, inject, drop. DEK cache with TTL (default 60 s, max 1000 entries, zeroized on evict). | No cache (KMS rate limit and latency); long-lived cache (larger blast radius) | A0-10 |
| 4 | **Bindings in gateway config (TOML)** for S3: `secret_id`, allowed `scheme://host[:port]`, header name and template. Moves to the database with the policy engine (T2). | A bindings table now (needs the policy model that T2 defines; premature) | roadmap T2 |
| 5 | **Egress rules:** exact host allowlist from the binding; refuse private, loopback and link-local resolved addresses unless `allow_private_hosts` names the mock upstream; pin the connection to the validated address (no DNS rebind); redirects are not followed. | Following redirects and re-checking (more surface for the first slice); trusting the URL text only | `ls-proxy` network guard; OWASP SSRF cheat sheet |
| 6 | **Redaction:** run `ls-redact` on response headers and body before returning, including after decompression; if the body cannot be safely scanned (unsupported content-encoding, size over limit) return 502 rather than pass it through. | Pass-through of unknown encodings (fails open) | `ls-proxy` decompress support; `ls-redact` tests |
| 7 | **Caller auth for S3:** one static bearer token from config, compared in constant time. S4 replaces it with agent identity. | No auth (open relay) | S4 scope in roadmap |
| 8 | **Audit:** append-only `gateway_audit` table (no UPDATE/DELETE grant, RLS by `org_id`), written in the same request path; the value, headers and query string are never stored. S5 moves this into the hash chain. | Logs only (not queryable, easy to lose); building the chain now (S5) | roadmap S5 |
| 9 | **Honest label:** relay is *containment plus prevention of direct reads*: the caller cannot read the value from any API, but a compromised gateway or an upstream that stores the secret elsewhere is out of scope. Redaction is best-effort detection of encodings we know. | Claiming the value cannot leak | `openspec/config.yaml` rule on honest labels |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| axum | MIT | already in workspace | n/a | service framework (same as control plane) | not AGPL |
| reqwest (rustls, no redirects) | MIT/Apache-2.0 | 0.13.5 (in lockfile) | 2026-09-08 | upstream calls | not AGPL |
| ls-envelope, ls-redact, ls-proxy (workspace) | project | workspace | n/a | decrypt, redaction, network guard | ours |
| subtle | BSD-3-Clause | latest in lockfile; re-check at apply | re-check | constant-time token compare | not AGPL |
| wiremock | MIT/Apache-2.0 | re-check at apply | re-check | dev-only upstream stand-in for unit tests | not AGPL |

Built in-house: the relay handler and binding checks, because they touch plaintext. Searched first: `hudsucker` (MITM, wrong shape), `pingora` (reverse proxy), Envoy (external process, injection would need Lua or WASM). The apply session re-checks every version against crates.io.

## Risks / Trade-offs
- [Upstream echoes the secret in an encoding we do not match] → `ls-redact` covers plain, base64, URL, hex; S6 adds adversarial encodings; labelled detection.
- [SSRF through DNS rebind] → connect to the validated IP; tested with a rebinding stub.
- [Static caller token is weak] → S3-only, loopback or compose network only; S4 replaces it.
- [DEK cache holds keys in memory] → short TTL, zeroize, no swap-sensitive pages beyond existing `zeroize` practice.

## How an agent debugs this
- `just up` then `just gateway` (service) and `just relay-smoke` (the e2e).
- Traces in Grafana/Tempo (via mcp-grafana): span `relay` with attributes secret id, host, outcome; never the value.
- Postgres MCP: `select * from gateway_audit order by at desc limit 20`.
- OpenBao audit log shows decrypt calls by token, proving only the gateway decrypts.
- `just leak-scan` over DB, Loki, Tempo and transcripts.
