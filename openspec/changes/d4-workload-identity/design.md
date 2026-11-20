# Design: D4 workload identity

## Context
- See proposal.md (Why). Shipped and reused:
  - Agent tokens (`services/control-plane/src/agent_token.rs`): 15-minute EdDSA JWTs, audience `gateway`, claims `sub` (agent), `org`, `iat`, `exp` only. Minted by `POST /v1/agent-tokens` after an Argon2id check of the enrollment secret (`api/agents.rs::mint`, `enrollment.rs`). The gateway verifies them through `/.well-known/jwks.json` and checks grants on every call.
  - Generic OIDC verification from T1: `auth/jwks.rs` (`JwksCache`: kid lookup, rate-limited refresh, size cap, stale-key expiry, algorithm from key type) and `auth/human.rs` (issuer/audience/leeway, algorithm allow-list). Today both serve exactly one configured human issuer.
  - `agents` and `agent_grants` tables (`migrations/0006_agents.sql`: RLS, composite FKs on `org_id`, cascade deletes), `with_org` tenant closures, the audit ledger (`crates/ls-audit` event codes, `audit.rs`), human auth binding an org to a request.
- Gap: no way to prove "this is job X of repo Y" without a stored enrollment secret, and `JwksCache` cannot serve many per-org issuers.
- Principle: the workload never gets anything new. It gets an ordinary agent token for an existing agent, so grants and every gateway feature apply unchanged.

## Goals / Non-Goals
**Goals:** trust policies per org; verified exchange of a GitHub Actions or Kubernetes OIDC token for an agent token; claim matching that cannot be written too loosely; audit; CLI, GitHub Action, console and desktop pages.
**Non-Goals:** other clouds or CI vendors, SPIFFE, ABAC/Cedar, operator or CSI, anything returning a secret value (see proposal Out of scope).

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **Exchange for an ordinary agent token of an existing agent.** A policy links an issuer and claim conditions to an `agent_id`; `POST /v1/workload-tokens` returns the same `AgentToken` shape. No new token type, no gateway change. | A new "workload token" with its own claims and gateway path (duplicates grant checks, widens gateway surface); minting grants directly from external claims (access decided outside the grant table). | S4 design decisions 1 and 4; `agent_token.rs` claims are ids and times only. |
| 2 | **The request carries a non-secret routing handle `lsw_<base64url(org_id\|policy_id)>` plus the external JWT.** The control plane opens the org under RLS with the handle, loads that one policy, and only then verifies the JWT against that policy's issuer. | Look policies up by `iss`/`sub` across all orgs (needs a RLS bypass or a cross-tenant index, violates A0-4); put the org in a custom token claim (not available from GitHub or kubelet). | Same pattern as the `lse_` enrollment secret, whose ids are routing data (`enrollment.rs`); A0-4, A0-5. |
| 3 | **Issuer and keys come only from the stored policy.** `github` fixes the issuer to `https://token.actions.githubusercontent.com`; `oidc` (Kubernetes and others) takes an explicit `https` issuer URL. JWKS is found via `<issuer>/.well-known/openid-configuration`, fetched through the existing address guard with size/time caps; the token's `iss`, `jku` and `x5u` are never followed. A per-issuer `JwksCache` is created lazily and shared across policies. Local dev may allow private issuer hosts by an explicit config flag. | Trust whatever issuer the token names (SSRF and forged-issuer risk); static pasted JWKS only (kept as a later option for air-gapped clusters). | GitHub OIDC docs (docs.github.com/en/actions/concepts/security/openid-connect), Kubernetes bound service account tokens and `/openid/v1/jwks` (kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/), OWASP SSRF guidance; gateway address guard (`egress::address_allowed`) already exists. |
| 4 | **Claim conditions are exact match, or one trailing `*` on a value, on named claims.** At least one condition must pin the subject: `repository` (GitHub) or `sub` (generic, covers Kubernetes `system:serviceaccount:<ns>:<name>`); a bare `*` or a policy with no subject pin is refused at create time. All conditions must match (AND). GitHub presets also offer `ref`, `environment`, `job_workflow_ref`, `repository_owner_id`. Kubernetes presets are `namespace` and `serviceaccount`, compiled to the `sub` string. | Regex or CEL (ReDoS and expressive footguns, T2 owns policy language); defaulting to org-wide `repo:acme/*` (GitHub's own docs warn a broad `sub` lets any repo in the org assume the role). | GitHub docs "configuring OpenID Connect": customising `sub` and pinning `repository`, `ref`, `environment`; provider documentation for AWS/Vault/Azure uses the same pinning guidance. |
| 5 | **Audience is per policy**, default the control plane's public URL; GitHub's `audience` parameter and a Kubernetes projected token `audience` are set to it by `smith`. Tokens without it are refused. | Accept any audience (token meant for another service could be replayed here). | OIDC Core 3.1.3.7, RFC 8725 section 3.1 (JWT best current practice). |
| 6 | **Replay and abuse limits:** reject external tokens with `exp - iat` over a max (default 1 h; GitHub issues about 10 min, projected k8s tokens at least 10 min), cache `jti` for the token lifetime in an in-memory TTL map when present (best effort, per replica; documented), and rate limit per policy and per source address. | Persisting `jti` in Postgres on every exchange (write per login for little gain: the minted token is short-lived anyway); no limits. | RFC 8725 sections 3.8 and 3.10; agent-token TTL is already 15 min, so replay window is bounded. Honest label: **containment**. |
| 7 | **One policy match, fail closed.** The handle selects the policy, so there is no first-match ambiguity. Every failure (unknown handle, bad signature, wrong aud, claim mismatch, expired, replay, issuer down) returns the same `401`; the reason slug is only in the audit event and span. | Distinct error bodies (oracle for probing policies, same rule as `mint_token`). | `api/agents.rs::Outcome`; T1 spec "401 that does not say why". |
| 8 | **Audit every outcome, no token text:** `workload_identity.created`, `.deleted`, `.exchanged`, `.denied` with policy id, agent id, issuer, reason slug and only the identifying claims the policy names. | Logging the full external claim set (can include actor names, emails; unnecessary). | S5 ledger conventions; `ls-audit` codes; leak-scan canaries. |
| 9 | **`smith login --workload github\|kubernetes`** takes the policy handle (`--policy` or `LOCKSMITH_WORKLOAD_POLICY`, non-secret), fetches the external token (GitHub: `ACTIONS_ID_TOKEN_REQUEST_URL` plus `&audience=`, bearer `ACTIONS_ID_TOKEN_REQUEST_TOKEN`; Kubernetes: a projected token file path), exchanges it, writes only the agent token to the existing 0600 `agent.json`. The external token lives in a `secrecy` type for one call. A thin composite action wraps it. | An action that stores an enrollment secret (the thing we are removing); a long-lived refresh token. | GitHub docs for the runner request variables; `smith-cli/src/connector.rs` login flow. |

## Data and API shape
```sql
workload_identities(
  id uuid pk (uuidv7), org_id uuid not null,
  name text not null, issuer_kind text check in ('github','oidc'),
  issuer text not null, audience text not null,
  agent_id uuid not null,   -- composite FK (org_id, agent_id) ON DELETE CASCADE
  conditions jsonb not null, -- [{claim, op: eq|prefix, value}], validated in Rust
  created_by uuid, created_at, last_used_at,
  unique (org_id, name)
) -- ENABLE and FORCE ROW LEVEL SECURITY, tenant_isolation policy (A0-4)
```
Routes (OpenAPI first): `POST/GET /v1/workload-identities`, `GET/DELETE /v1/workload-identities/{id}` (human auth, org from the session); `POST /v1/workload-tokens` (no human auth; body `{policy, token}`, or `Authorization: Bearer <jwt>` plus `policy`). `last_used_at` is updated with a coarse throttle, not on every call.

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| jsonwebtoken (already a dependency) | MIT | per Cargo.lock | n/a | verify external JWTs with an explicit algorithm allow-list | not AGPL |
| reqwest, wiremock (already used by `auth/jwks.rs` and its tests) | MIT/Apache-2.0 | per Cargo.lock | n/a | JWKS and discovery fetch; stub issuer in tests | not AGPL |
| moka or a small `HashMap` TTL (decision 6) | MIT/Apache-2.0 | **[verify]** at apply | **[verify]** | `jti` cache; prefer an existing workspace dependency if one has a TTL cache | not AGPL |
| rcgen / test signing keys (dev only) | MIT/Apache-2.0 | per Cargo.lock | n/a | stub OIDC issuer keys | not AGPL |

**[verify]** at apply: whether the `jti` cache needs a new crate or an existing workspace dependency covers it; record the choice here. Built in-house: only the policy model, condition matcher, per-issuer cache registry and the exchange glue. Searched first: GitHub OIDC verification crates and OIDC clients (`openidconnect` is a relying-party client for the authorization flow and does not model per-policy claim checks; generic JWKS verification is already in-tree from T1), and SPIRE (Apache-2.0; deferred to a later phase per `docs/research/oss-building-blocks.md` "Workload identity").

## How an agent debugs this
`just up`, `just api`, `just gateway`, then `just workload-smoke` (stub issuer plus `smith login --workload`). Ledger: `GET /v1/audit/events` filtered to `workload_identity.*` and `just audit-verify`; `just leak-scan` for canaries. Control-plane spans `exchange_workload_token` (attributes `policy.id`, `agent.id`, `outcome`, never a token) in Tempo and logs in Loki via the Grafana MCP. DB: `workload_identities` and `agent_grants` through the Postgres MCP (read-only). `smith doctor` reports the policy handle, issuer reachability and agent token expiry.

## Risks / Trade-offs
- A matching workflow can obtain the agent's grants for 15 minutes: any code running in an allowed repo and ref (including a compromised dependency in that job) can use them. Containment through pinning `repository`, `ref`, `environment`, narrow grants and short TTL; documented per provider.
- Over-broad policies are the main foot-gun: the subject pin rule, no bare `*` and the console's warning on prefix matches reduce it but cannot prevent `refs/heads/*`; docs recommend `environment` protection rules.
- `jti` replay cache is per replica and in memory: a replay against another replica inside the token lifetime still works, bounded by claim checks and the 15-minute agent token.
- Outbound JWKS fetches are an SSRF surface: mitigated by exact stored issuer, https-only, address guard, size and time caps.
- Self-hosted Kubernetes API servers are often private: the control plane may not reach their JWKS. Documented limit; static JWKS option is a follow-up.
