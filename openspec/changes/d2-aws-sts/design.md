# Design: D2 AWS STS credentials

## Context
- Shipped: `crates/ls-proxy/src/aws/sts.rs` (synchronous `ureq`, SigV4 via `aws::sigv4`) already implements `assume_role`, `contained` (15 min credentials limited by a session policy) and `revoke_older_sessions`, with tests against a mock HTTP server (`crates/ls-proxy/tests/aws_sts.rs`). `smith aws creds --contained` and `doctor_m7.rs` use it locally. Policy translation lives in `aws/policy.rs`.
- The hosted gateway (`services/gateway`) has agent-token auth, grant cache, binding checks, decrypt, redaction and ledger audit for `/v1/relay`, but no AWS route.
- Agents hold only an agent token (S4). Credentials for AWS are the one allowed exception (H1-2): short-lived, scoped, off by default.

## Goals / Non-Goals
**Goals:** `POST /v1/aws/credentials` in the gateway; `smith aws setup|credential-process|teardown`; a Floci service in the local stack; ledger events; console and desktop show AWS bindings.
**Non-Goals:** hosted re-signing relay, per-action policy language, cloud deployment, web-identity federation.

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **Vend STS credentials from the gateway with `AssumeRole` plus an inline session policy** built from the grant, 900 s default, 3600 s maximum, never the role's full permissions. | Hand out the stored long-lived key (violates H1-2); a hosted SigV4 re-signing proxy (streaming S3 signing and a vendored operation table in the hosted path is a large new surface; the local M7 relay stays for that). | AWS STS AssumeRole docs (docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html): session policies can only narrow the role; 15 minute minimum. In-tree `ls-proxy::aws::sts` proves the call. |
| 2 | **AWS CLI integration through `credential_process`** (`smith aws credential-process` prints the documented JSON `Version/AccessKeyId/SecretAccessKey/SessionToken/Expiration`). | Exporting `AWS_*` env vars (lands in `env`, `ps`, shell history); a wrapper binary around `aws`. | AWS CLI sourcing credentials with an external process (docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html); the CLI caches nothing it must not, and SDKs honour the same setting. |
| 3 | **Gateway holds the base credential or the role's trust**, stored as a sealed secret of kind `aws-assume-role` (role ARN, external id, base key). Agent token only reaches `/v1/aws/credentials`. | Per-agent IAM users (does not scale, long-lived keys); letting the agent call STS itself (needs a base key). | Envelope-encryption spec; AGENTS.md "agents never receive secret values". |
| 4 | **Grant carries allow-lists** (`actions`, `resources`, `max_duration_secs`); the gateway renders them into the session policy and refuses an empty or `*:*` grant unless the binding explicitly says `unrestricted`. | Passing the agent's requested policy through (lets the agent widen scope within the role); a policy DSL now (T2). | STS session-policy rules; M7 `policy.rs` already translates allow rules. |
| 5 | **Tool is off by default**: a binding must set `vend = true` and the grant must carry mode `delegate`; doctor warns that the credentials are agent-visible. | Always on for any AWS binding. | Owner decision H1-2 (`openspec/decisions.md`). |
| 6 | **Test on Floci** (`motoserver/Floci` in compose) with `AWS_ENDPOINT_URL_STS` pointed at it; the gateway's STS endpoint is configurable for tests only. | LocalStack (licence and account requirements changed in 2025/2026; Floci is Apache-2.0 and named in A0-14); the existing hand-rolled mock only. | A0-14 and roadmap row D2; Floci STS and IAM support (docs.getmoto.org). **[verify]** at apply that Floci's AssumeRole returns usable temporary keys and which session-policy and IAM checks it enforces: enforcement of the session policy likely needs `MOTO_IAM_LOAD_MANAGED_POLICIES`/IAM auth mode, otherwise the policy sent is asserted from the captured request and enforcement is left to the P1 smoke check. |
| 7 | **Reuse and extend `ls-proxy::aws::sts`** (move the async-callable core to a small `ls-aws` helper only if the gateway cannot call the blocking version through `spawn_blocking`). | Rewriting SigV4 or pulling the full `aws-sdk-sts` (large dependency tree; the in-tree signer is tested against the AWS SigV4 suite). | Existing tests in `crates/ls-proxy/tests/aws_sts.rs` and `tests/fixtures/sigv4`. |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| Floci (`motoserver/Floci` image) | Apache-2.0 | **[verify]** pin at apply | **[verify]** | local STS and IAM stand-in (A0-14) | test-time container, not linked |
| ureq (workspace, via `ls-proxy`) | MIT/Apache-2.0 | 3.x workspace | n/a | existing STS HTTPS calls | not AGPL |
| axum (workspace) | MIT | workspace | n/a | the gateway route | not AGPL |
| awscli v2 (test tool only) | Apache-2.0 | **[verify]** system | n/a | real CLI end-to-end through `credential_process` | not shipped |
| aws-sdk-sts | Apache-2.0 | not used | n/a | considered, rejected (decision 7) | n/a |

Built in-house: the route glue, session-policy rendering from a grant and the `credential-process` subcommand. Searched first: a maintained Rust STS credential-vending proxy and `aws-vault` style tools (MIT/Go, local user keychain model, no hosted gateway or grants); none fits a gateway holding the base credential.

## How an agent debugs this
`just up` (adds Floci on its published port) and `just api`; run `just gateway`; `just aws-smoke`. Ledger: `GET /v1/audit/events` (`aws.credentials.issued`, `aws.credentials.denied`), `just audit-verify`, `just leak-scan`. Inspect Floci with `curl $MOTO/Floci-api/` and `aws --endpoint-url $MOTO sts get-caller-identity`. Gateway spans in Tempo and logs in Loki through the Grafana MCP; `smith doctor` reports the `aws.vend` check. DB tables: grants and bindings in the control plane (`just psql` or the Postgres MCP).

## Risks
Credentials are visible to the agent for their lifetime (contained by session policy and expiry; stated in the notice and docs). Floci may not enforce session policies (decision 6), so enforcement is proven in the P1 smoke check. Clock skew breaks SigV4 (the STS call uses the gateway clock). A hostile upstream echoing credentials is not applicable: the response goes to the caller by design, but the base credential must never appear in it (a test asserts this).
