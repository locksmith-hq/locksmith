# Tasks: D4 workload identity

## 1. Policy model and storage [sonnet]
- [ ] 1.1 Migration `0012_workload_identities.sql` (shape in design.md): RLS enabled and forced, `tenant_isolation` policy, composite FK to `agents (org_id, id)` with cascade, grants to `locksmith_app`; covered by the existing tenant lint.
- [ ] 1.2 `services/control-plane/src/workload.rs`: `IssuerKind`, `Condition`, create-time validation (https issuer, fixed GitHub issuer, subject pin required, bare `*` refused, trailing-`*` only, audience required) as pure functions with unit tests; `lsw_` handle encode/parse mirroring `enrollment.rs`.
- [ ] 1.3 Handlers `POST/GET /v1/workload-identities`, `GET/DELETE /v1/workload-identities/{id}` under human auth and `with_org`, utoipa annotations, `workload_identity.created` and `.deleted` audit events (add codes in `crates/ls-audit/src/event.rs`).
- [ ] 1.4 Regenerate the OpenAPI document and `packages/control-plane-client` types (`just api-types`); add fixtures for the new routes.
- [ ] 1.5 Verify: `cargo nextest run -p ls-control-plane workload` and `cargo nextest run -p ls-control-plane tenant_lint` (cross-org agent id is `404`, unpinned policy is `422`).

## 2. Issuer verification and claim matching [opus]
- [ ] 2.1 Per-issuer `JwksCache` registry in `services/control-plane/src/auth/` keyed by stored issuer URL: OpenID discovery, https-only, address-guarded client, size and time caps, local-dev private-host flag; reuses the `jwks.rs` cache unchanged.
- [ ] 2.2 `verify_external(token, policy)`: header and algorithm allow-list (no `none`, no HS*), `kid` lookup with one rate-limited refresh, `iss` equals the stored issuer, `aud` equals the policy audience, `exp`/`nbf` with leeway, `exp - iat` cap; token never in errors.
- [ ] 2.3 Condition matcher (exact and trailing `*`, AND semantics, missing claim fails) with table-driven tests including GitHub sample claim sets and the Kubernetes `sub` form.
- [ ] 2.4 Verify: `cargo nextest run -p ls-control-plane workload_verify` against a wiremock stub issuer: valid, expired, wrong aud, wrong iss, alg none, HS256 confusion, unknown kid, rotated key, issuer down, issuer at a private address.

## 3. Token exchange endpoint [sonnet]
- [ ] 3.1 `POST /v1/workload-tokens`: parse `{policy, token}` with the token read into a `SecretString` newtype (no Debug, Display, Clone, Serialize), load the policy under RLS, verify, match, then mint via the existing `AgentTokenSigner::mint`; `Cache-Control: no-store`; a single `401` for every failure with the reason only on the span.
- [ ] 3.2 Spans and audit: `exchange_workload_token` span (policy, agent, outcome), `workload_identity.exchanged` and `.denied` events with only policy-named claims; throttled `last_used_at` update.
- [ ] 3.3 Verify: `cargo nextest run -p ls-control-plane workload_exchange`: minted token verifies with the gateway verifier, carries only the agent claims, policy delete and grant revoke cut access, every failure body is identical.

## 4. Abuse limits and adversarial cases [sonnet]
- [ ] 4.1 `jti` replay cache (decision 6; resolve the `[verify]` OSS item first) and per-policy plus per-source rate limits with config defaults.
- [ ] 4.2 Add cases to `tests/adversarial/`: forged `iss` pointing at an attacker host (no outbound call), `jku` header ignored, token for another audience, replayed `jti`, policy handle for another org, canary external token absent from logs, traces and ledger.
- [ ] 4.3 Verify: `cargo nextest run -p ls-control-plane workload_abuse`, `bash tests/adversarial/run.sh`, `just leak-scan`.

## 5. CLI and GitHub Action [sonnet]
- [ ] 5.1 `smith login --workload github|kubernetes` with `--policy` / `LOCKSMITH_WORKLOAD_POLICY`: fetch the external token (runner request variables with `audience`; projected token file), exchange, write only the agent token via the existing `agent.json` path; token in `secrecy` types, never in argv, output or disk.
- [ ] 5.2 `smith doctor` check `workload` (policy handle present, issuer reachable, agent token expiry); help text.
- [ ] 5.3 `integrations/github-action/action.yml`: composite action that installs `smith` and runs `smith login --workload github`; README with the required `permissions: id-token: write` and a pinned-policy example; `scripts/tree-check.sh` stays green.
- [ ] 5.4 Verify: `cargo nextest run -p smith-cli workload` (stub runner endpoint and token file; asserts no file other than `agent.json` is written and the external token appears in no output).

## 6. Console and desktop [sonnet]
- [ ] 6.1 Workload identities page in `apps/web` (list, create form with issuer presets for GitHub and Kubernetes, delete with confirm, warning on prefix conditions); no token or secret field anywhere.
- [ ] 6.2 Same page in `apps/desktop` using the shared client; Vitest tests for both including the "no secret rendered or requested" assertion.
- [ ] 6.3 Verify: `npm test --workspace apps/web` and `just apps-build`.

## 7. Local verification [sonnet]
- [ ] 7.1 `just workload-smoke` recipe and `tests/e2e/tests/workload.rs`: start the stack, serve a stub GitHub-shaped issuer, create an agent, grant and a workload policy through the API, run `smith login --workload github` against the stub runner endpoint, relay a request to the canary upstream, assert the upstream saw the secret and the workload held no Locksmith secret; then assert a non-matching `ref` and a revoked grant are refused.
- [ ] 7.2 `just up`, `just workload-smoke`, `just apps-build`, then `just ci`.
