# Design: S4 agent connector

## Context
- S3 (in review, PR 168) adds `services/gateway`, the internal material endpoint, `gateway_audit` and a static caller token.
- Existing inventory: `crates/smith-cli` (vault, run, http commands; hook and session code), `crates/locksmith-mcp` (stdio MCP server), `ls-hooks` (agent adapters). These target the local vault; S4 adds a remote mode, not a rewrite.
- S1 gives the org-scoped tenant helper and OpenAPI generation. A0-15: services verify JWTs through JWKS only.
- Binding decisions: A0-4, A0-5, A0-15.

## Goals / Non-Goals
**Goals:** first demo, an agent using a credential it never holds; identity and grant model that T2 policy and T4 approvals extend.
**Non-Goals:** human login, Cedar policy, approvals, delegate/inject modes, audit chain.

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **Agent token = EdDSA JWT minted by the control plane**, 15 min, `aud=gateway`, claims `sub` agent id, `org`, `exp`. Gateway verifies via JWKS with `jsonwebtoken`. | Opaque tokens with introspection (extra hop per call); reusing human OIDC (T1 not built; agents are not humans) | A0-15; RFC 7519, RFC 8037 (EdDSA in JOSE) |
| 2 | **Agent bootstrap:** registration returns a one-time enrollment secret, shown once, stored hashed (argon2id via existing `ls-crypto`); "one-time" means shown once, then reusable for token exchange until rotated (`POST /v1/agents/{id}/enrollment-secret`) or the agent is deleted (a single-use secret would strand the agent after its 15 min token); `smith login --agent` exchanges it for tokens. | Long-lived API key in env (the agent would hold a reusable credential); mTLS (heavy for a first slice) | OWASP secrets management cheat sheet |
| 3 | **Enrollment secret is not a vault secret** and is never placed in the agent's reach by Locksmith; the human or launcher supplies it to `smith`, which keeps only the short-lived token in memory/state dir (0600). Honest label: containment, not prevention (a compromised agent can use its token until expiry). | Claiming the token is safe | `openspec/config.yaml` honesty rule |
| 4 | **Grants are rows** (`agent_grants`: agent, secret binding id, mode=`relay`, expires_at) with RLS and `org_id`; the gateway reads them through a control-plane internal endpoint with caching of at most 10 s. | Grants in gateway TOML (no revocation); direct DB read by the gateway (S3 decision 2) | S3 design decisions 2 and 4 |
| 5 | **MCP tools `list_grants` and `relay_request`**; `smith relay` mirrors them. Reuse the existing `locksmith-mcp` server and add a remote backend. | New MCP server crate (duplicates transport); `rmcp` rewrite (out of scope) | `crates/locksmith-mcp/src/main.rs` |
| 6 | **Thin console page** lists agents and grants and creates grants, so the demo is visible and apps stay green. Full console is T3. | Defer all UI (breaks the every-change apps rule) | `openspec/config.yaml` apps rule |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| jsonwebtoken | MIT | 12.0.0 | 2026-11-13 | sign and verify EdDSA JWTs | not AGPL |
| ed25519-dalek | BSD-3-Clause | 3.0.0 | 2026-07-06 | signing key (chosen over ring: pure Rust, no C build) | not AGPL |
| argon2 (RustCrypto) | MIT/Apache-2.0 | 0.5.3 in lockfile (0.6.0 released 2026-08-27) | 2026-08-27 | hash enrollment secret; stay on the lockfile version unless `ls-crypto` upgrades | not AGPL |
| axum, reqwest | MIT | workspace (as S3) | n/a | services and clients | not AGPL |
| subtle | BSD-3-Clause | 2.6.1 (lockfile) | 2024-06-24 | constant-time compare | not AGPL |

Built in-house: grant check and token minting glue, because they gate decryption. Searched first: Ory Hydra and Keycloak client-credentials (extra service for a slice that only needs one signed token). Versions above were checked on crates.io on 2026-11-17; apply re-checks them.
SDK-licence note: `smith-cli` and plugins are Apache-2.0; they use only permissive crates.

## Risks / Trade-offs
- [Stolen agent token] → 15 min expiry, grant revocation takes effect within the 10 s cache TTL, audit shows the agent id.
- [Signing key exposure] → key held by the control plane only, JWKS publishes the public half, rotation by `kid`; KMS-backed signing deferred to P1.
- [Token or enrollment secret in transcript] → `smith` redacts its own output; leak-scan includes the transcript.

## How an agent debugs this
- `just up`, `just gateway`, then `just connector-smoke`.
- Postgres MCP: `select * from agents`, `agent_grants`, `gateway_audit order by at desc`.
- Grafana/Tempo spans `mint_token`, `verify_token`, `relay` (attributes: agent id, outcome; never values).
- `smith grants --json` and the MCP `list_grants` tool show exactly what the agent sees.
- `just leak-scan` over DB, Loki, Tempo, files and the Claude transcript.

- [Unauthenticated token endpoint runs Argon2id] → needs a rate limit or concurrency cap before exposure (follow-up, not yet done). JWKS publishes only the current key; kid-overlap rotation is part of task 2.1.
