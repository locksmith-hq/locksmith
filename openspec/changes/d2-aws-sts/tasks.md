# Tasks: D2 AWS STS credentials

## 1. Moto and spike [sonnet]
- [x] 1.1 Add `motoserver/moto` (pinned, record version and release date in design.md) to `infra/compose/compose.yaml` and `.env.example`; `just up` starts it and `harness-check` reports it.
- [x] 1.2 [opus] Spike `tests/e2e` against moto: AssumeRole returns usable keys; record in design.md which session-policy and IAM checks moto enforces and decide how enforcement is asserted (captured request vs moto IAM mode).
- [x] 1.3 Verify: `just up && curl -fsS localhost:5000/moto-api/` and the spike test pass.

## 2. Session policy and binding model [sonnet]
- [x] 2.1 Define the AWS binding shape (role ARN, region, external id, `vend`, `unrestricted`, max duration) and the grant allow-list in the gateway config and control-plane types with fixture data; document in design.md.
- [x] 2.2 `render_session_policy(grant)`: actions and resources only, empty grant refused, size limit checked (STS 2048 packed characters); proptest that output never widens the grant.
- [x] 2.3 Verify: `cargo nextest run -p ls-gateway aws_policy`.

## 3. Gateway route [opus]
- [x] 3.1 `services/gateway/src/aws.rs`: `POST /v1/aws/credentials`: agent token, `delegate` grant and `vend` checks, duration clamp, all before decrypt; fail closed when the ledger append fails.
- [x] 3.2 Call STS through `ls-proxy::aws::sts::assume_role` (via `spawn_blocking`) with the rendered policy and configurable endpoint (tests only); base credential held in secrecy types and dropped after the call.
- [x] 3.3 Fixed error slugs, redaction check of the response for the base credential, ledger events `aws.credentials.issued` and `.denied` with role, region, duration and outcome only.
- [x] 3.4 Verify: `cargo nextest run -p ls-gateway aws` against moto: success, unbound 403, no-vend 403, relay-only 403, empty grant 403, STS error slug.

## 4. Client [sonnet]
- [x] 4.1 `smith aws credential-process` (prints the documented JSON, caches nothing on disk, exits non-zero with a fixed message on denial) and `smith aws setup|teardown` writing and removing a keyless profile.
- [x] 4.2 `smith doctor` check `aws.vend` (profile present, no long-lived keys in `~/.aws`, off-by-default warning); MCP and CLI help text.
- [x] 4.3 Verify: `cargo nextest run -p smith-cli aws`.

## 5. Console and desktop [sonnet]
- [ ] 5.1 Show AWS bindings (role, region, allowed actions, `vend`, max duration) on the bindings page in `apps/web` and `apps/desktop` with Vitest tests; no credentials displayed.
- [ ] 5.2 Verify: `npm test --workspace apps/web` and `just apps-build`.

## 6. Adversarial and audit [sonnet]
- [ ] 6.1 Add AWS cases to `tests/adversarial/cases`: agent-supplied policy ignored, over-duration, STS error echo, base credential absent from every output.
- [ ] 6.2 Verify: `bash tests/adversarial/run.sh`, `just leak-scan`, `just audit-verify`.

## 7. Local verification [sonnet]
- [ ] 7.1 `just aws-smoke` recipe: start moto, gateway and API, register an agent, grant, run the real `aws` CLI through `credential_process`, assert identity, expiry and that the agent home holds no key.
- [ ] 7.2 `just up`, `just aws-smoke`, `just apps-build`, then `just ci`. Record the P1 named check for session-policy enforcement on real AWS in progress.md.
