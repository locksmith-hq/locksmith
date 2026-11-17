# Locksmith Roadmap (v2, 2026-11-16)

Replaces roadmap v6. The v6 OpenSpec is preserved under git tag `openspec-v6`.

**Product:** an open-source secrets platform whose core is agent access. A coding agent uses
credentials through a gateway and never holds them. The control plane stores only ciphertext, and
values are decrypted only inside a gateway. Competitive basis: [research/infisical.md](research/infisical.md).
Building blocks: [research/oss-building-blocks.md](research/oss-building-blocks.md).

## How we work

1. **Harness first.** Before any product code there is a local stack and the tools an agent needs to see
   inside it: DB, logs, traces and leak scans. Every later change is tested through that harness.
2. **Thin vertical slices.** Each change ships something runnable in `just up` and a smoke test that proves it.
3. **Evidence and reuse.** Each design cites its sources and lists the open-source packages it uses
   (`openspec/config.yaml` enforces this). We build only what touches plaintext or defines the product.
4. **Existing code is inventory, not spec.** These crates are reused where a change says so:
   - `ls-proxy` (HTTP injection, network guard, AWS)
   - `ls-redact` (response redaction)
   - `ls-crypto` (AEAD, KDF)
   - `ls-vault` (audit hash chain)
   - `smith-cli`, `locksmith-mcp`, `ls-hooks` (agent connector and hooks)
5. **Local, then cloud.** AWS `dev` arrives only in phase 4. Until then LocalStack stands in for AWS.
6. **Model tiers.** Sonnet runs by default. Tasks marked `[opus]` touch crypto, auth, the gateway or adversarial gates.

Status: ☐ not started · ◐ in progress · ☑ archived. Only the next one or two changes are written in
full. Later rows are proposed (`/opsx:propose`) when their predecessor is about done, so each one
uses what the previous one taught us.

## Phase 0: Harness (make the system observable to agents)

| # | Change | Usable outcome | Local gate | Status |
|---|---|---|---|---|
| F0 | `f0-dev-harness` | `just up` starts Postgres, an OTel/Grafana stack (logs, traces, metrics) and a mock upstream API. Claude Code can query the DB and the logs through MCP servers in `.mcp.json`. | `just up && just harness-check` | ☑ |
| F1 | `f1-test-kit` | Canary secrets, `just leak-scan` (scans DB, logs, traces, files and transcripts for every encoding of a canary), nextest, snapshot tests, testcontainers and the `tests/e2e` skeleton. | `just leak-scan` fails on a planted canary and passes on a clean stack | ☑ |
| A0 | `a0-data-and-cloud-foundations` [opus] | Hard-to-change DB and AWS choices are decided with sources and proven by spikes: Postgres 18, RLS tenancy, UUIDv7, the versioned ciphertext header, regions, KMS, account layout. **Owner approval required before S1.** | `cargo nextest run -p a0-spikes` | ☐ |

## Phase 1: First vertical slice (one agent, one secret, one API, zero exposure)

| # | Change | Usable outcome | Local gate |
|---|---|---|---|
| S1 | `s1-control-plane-skeleton` | axum service with Postgres migrations, an OpenAPI spec, health checks and OTel. Orgs, projects, environments and secret metadata through the API. | API e2e against compose, OTel traces visible in Grafana |
| S2 | `s2-envelope-crypto` [opus] | Secret versions are encrypted under a per-version DEK, which is wrapped to a gateway key held in a KMS (LocalStack KMS or OpenBao transit locally). The control plane cannot decrypt. | Crypto KATs, `just leak-scan` on the DB, decrypt-fails-in-control-plane test |
| S3 | `s3-gateway-http` [opus] | The gateway (from `ls-proxy`) unwraps the key, injects the secret into a call to the mock upstream, redacts the response and writes an audit record. | Mock upstream receives the secret, and the agent side and logs contain no canary |
| S4 | `s4-agent-connector` | Agent identity plus short-lived token. `smith` and `locksmith-mcp` list grants and route tool calls through the gateway. **First demo: Claude Code calls a real API (e.g. Langfuse) with no key on the laptop.** | Live headless `claude -p` run, `just leak-scan` on the transcript |
| S5 | `s5-audit-ledger` | Append-only, hash-chained audit per org. `just audit-verify` checks it and an export goes to a file sink. | Tamper test |
| S6 | `s6-adversarial-gate-1` [opus] | Scripted and live-agent extraction attempts against S1–S5 (env, reflection, header echo, encodings). | Suite green in CI and nightly |

## Phase 2: Team product

| # | Change | Usable outcome |
|---|---|---|
| T1 | `t1-human-auth` | Human sign-in with OIDC and passkeys through the chosen IdP (decided by spike in the design). |
| T2 | `t2-policy-engine` [opus] | RBAC and ABAC using Cedar in-process. Usage modes per binding: relay, delegate, inject. |
| T3 | `t3-console-mvp` | React console: projects, secrets (client-side encrypted), agents, sessions and audit view. Playwright e2e. |
| T4 | `t4-access-proposals` | An agent requests access, a human approves in the console or CLI, and the grant is time-boxed. Kill switch. |
| T5 | `t5-honey-tokens` | Canary secrets that alert on any use and name the agent and its source. |

## Phase 3: Delegation beyond HTTP

| # | Change | Usable outcome |
|---|---|---|
| D1 | `d1-git-delegation` | The agent pushes to GitHub with no token in reach. |
| D2 | `d2-aws-sts` [opus] | The agent uses the AWS CLI through short-lived STS credentials. Tested on LocalStack first. |
| D3 | `d3-db-relay` [opus] | Postgres relay with no password on the agent host (pgwire). |
| D4 | `d4-workload-identity` | GitHub Actions and Kubernetes OIDC federation for CI and machine identities. |

## Phase 4: Deployable

| # | Change | Usable outcome |
|---|---|---|
| P1 | `p1-aws-dev-env` | OpenTofu `dev` environment on AWS: RDS, ECS or EKS, KMS, and OTel to Grafana Cloud free or self-hosted. The MCP servers point at it read-only. |
| P2 | `p2-packaging` | One-command self-host (compose and Helm), signed releases, `smith` installers. |
| P3 | `p3-sdks-and-plugins` | SDKs generated from OpenAPI, plus Claude Code, Cursor and Codex plugins. |

## Phase 5: Parity and beyond (ordered later, by demand)

Rotation and dynamic secrets (run in the gateway), syncs, the Terraform provider and k8s operator,
SAML and SCIM, billing, SOC2 programme, desktop app, local-only mode for solo developers.

## Phase 6: GA hardening

External pentest, full adversarial suite, Windows connector, docs and landing site.
