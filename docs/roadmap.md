# Locksmith Roadmap (v2, 2026-11-16)

Open-source plan only. The hosted SaaS (AWS environments, hosting, billing, SOC2) is planned in the private `locksmith-roadmap` and `locksmith-cloud` repos (owner decision 2026-11-22).

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
5. **Local, then cloud.** AWS `dev` arrives in phase 2, right after sign-in (P1; owner decision H1-3). Every AWS service has a local stand-in: `postgres:18` for Aurora, OpenBao for KMS, Floci (floci-io/floci) for S3, STS, Cognito and every other AWS API, Keycloak for OIDC. `dev` is capped at $5/month and is switched on only for test sessions (A0 decisions 14–18).
6. **Apps are built every change.** The web console and the desktop app (Tauri) grow with each slice
   instead of arriving at the end. Every change's Local verification runs `just apps-build`; the last
   change of each phase also runs the manual `ci-platforms` workflow on macOS and Linux (Windows parity is
   deferred to GA hardening, owner decision [#320](https://github.com/locksmith-hq/locksmith/issues/320)).
7. **Model tiers.** Sonnet runs by default. Only hard, complex tasks are marked `[opus]`; a change marked `[opus]` here is security-sensitive, but its tasks still run on Sonnet unless tagged `[opus]` in `tasks.md`.

Status: ☐ not started · ◐ in progress · ☑ archived. Parallel work comes first
(owner 2026-11-19): enough changes are written in full to keep at least three takeable, so every worker
has one. A row is proposed (`/opsx:propose`) as soon as it can start. The `Needs` column decides that: it lists
the changes whose code the row needs before work can begin (`-` for none), and the row can start once each
is archived or fully ticked on its branch. `<id>:contract` means the row needs only that change's contract
(API schema, shared types, mock data): it can start as soon as the "Contract" task group is ticked, and it
builds against the mocks until the real code lands. The lead keeps the column right; the PM keeps the row order.
`bash scripts/change-status.sh --plannable` prints the rows that can start today.

## Phase 0: Harness (make the system observable to agents)

| # | Change | Usable outcome | Local gate | Status |
|---|---|---|---|---|
| F0 | `f0-dev-harness` | `just up` starts Postgres, an OTel/Grafana stack (logs, traces, metrics) and a mock upstream API. Claude Code can query the DB and the logs through MCP servers in `.mcp.json`. | `just up && just harness-check` | ☑ |
| F1 | `f1-test-kit` | Canary secrets, `just leak-scan` (scans DB, logs, traces, files and transcripts for every encoding of a canary), nextest, snapshot tests, testcontainers and the `tests/e2e` skeleton. | `just leak-scan` fails on a planted canary and passes on a clean stack | ☑ |
| A0 | `a0-data-and-cloud-foundations` [opus] | Hard-to-change DB and AWS choices are decided with sources and proven by spikes: Postgres 18, RLS tenancy, UUIDv7, the versioned ciphertext header, regions, KMS, account layout, local parity for every AWS service, Cognito for users, and the $5/month `dev` budget. **Owner approval required before S1.** | `cargo nextest run -p a0-spikes` | ☑ |

## Phase 1: First vertical slice (one agent, one secret, one API, zero exposure)

| # | Change | Usable outcome | Local gate | Status |
|---|---|---|---|---|
| S1 | `s1-control-plane-skeleton` | axum service with Postgres migrations, an OpenAPI spec, health checks and OTel. Orgs, projects, environments and secret metadata through the API. | API e2e against compose, OTel traces visible in Grafana | ☑ |
| S2 | `s2-envelope-crypto` [opus] | Secret versions are encrypted under a per-version DEK, which is wrapped to a gateway key held in a KMS (OpenBao transit locally). The control plane cannot decrypt. | Crypto KATs, `just leak-scan` on the DB, decrypt-fails-in-control-plane test | ☑ |
| S3 | `s3-gateway-http` [opus] | The gateway (from `ls-proxy`) unwraps the key, injects the secret into a call to the mock upstream, redacts the response and writes an audit record. | Mock upstream receives the secret, and the agent side and logs contain no canary | ☑ |
| S4 | `s4-agent-connector` | Agent identity plus short-lived token. `smith` and `locksmith-mcp` list grants and route tool calls through the gateway. **First demo: Claude Code calls a real API (e.g. Langfuse) with no key on the laptop.** | Live headless `claude -p` run, `just leak-scan` on the transcript | ☑ |
| S5 | `s5-audit-ledger` | Append-only, hash-chained audit per org. `just audit-verify` checks it and an export goes to a file sink. | Tamper test | ☑ |
| S6 | `s6-adversarial-gate-1` [opus] | Scripted and live-agent extraction attempts against S1–S5 (env, reflection, header echo, encodings). | Suite green in CI and nightly | ☑ |
| X1 | `x1-apps-all-platforms` | The desktop app builds and launches on macOS and Linux, and the web console builds; `ci-platforms` builds the macOS bundle and the Linux bundle is built locally. Windows code (named pipe, ACLs) stays compile-checked only; runtime parity is deferred to GA hardening ([#320](https://github.com/locksmith-hq/locksmith/issues/320)). | `just apps-build` locally, `ci-platforms` green on macOS | ☑ |
| G1 | `g1-go-public` | The repo is ready to flip public: full-history secret scan triaged, AGPL/Apache licences in every manifest, a public README and community docs, `scripts/public-check.sh` in `just ci`, and an owner flip checklist. Only the owner flips visibility and re-enables `ci` (owner request [#147](https://github.com/locksmith-hq/locksmith/issues/147), [#307](https://github.com/locksmith-hq/locksmith/issues/307)). | `bash scripts/public-check.test.sh`, `gitleaks detect` clean | ☑ |
| H1 | `h1-test-recipes` | Every crate, service, app, package and integration has a documented test recipe: `docs/testing.md` maps each one to its command, `just test <name>` runs it, and tree-check fails when a new component has no entry. | `just test <name>` for every listed component, tree-check fails on a planted unlisted crate | ☑ |

## Phase 2: Team product

Order set by owner decision H1-3 ([#363](https://github.com/locksmith-hq/locksmith/issues/363)): sign-in first, then the cloud dev environment, then the console in slices, so a person can use the product in the cloud early. Design: [design/hub-technical-design.md](design/hub-technical-design.md).

| # | Change | Usable outcome | Needs | Status |
|---|---|---|---|---|
| T1 | `t1-human-auth` | Human sign-up and sign-in with email and password (verified email, reset), Google and GitHub: Amazon Cognito in our cloud, Keycloak locally, any OIDC issuer for self-hosters. GitHub is OAuth 2.0 rather than OIDC, so the design picks how Cognito and Keycloak broker it. Sign-up creates a personal org. Services only verify JWTs through JWKS (A0 decision 15). | - | ☑ |
| T3 | `t3-console-mvp` | React console shell on the real API, built from the mockup in `apps/web/src/mockup`: hub home, projects, environments, secret names and versions, agents, grants and activity. Design tokens move to `packages/ui`. No secret value entry yet. Playwright e2e. | t1-human-auth:contract | ☑ |
| T6 | `t6-org-members` | Organizations for teams: create an org, invite members by email, accept, remove or leave, and owner/admin/member roles that T2 policies build on. Web console and desktop pages. | t1-human-auth:contract, t3-console-mvp | ☐ |
| T7 | `t7-secret-write` [opus] | Add a secret or a new version from the browser, sealed in the browser before it is sent (decision H1-1). Changes the `envelope-encryption` spec: the API accepts only ciphertext. | t3-console-mvp | ☐ |
| T8 | `t8-sessions-and-revoke` | Live agent sessions are listed in the console; revoke one, revoke all, or pause every agent, and it takes effect within seconds. | t3-console-mvp | ☐ |
| T2 | `t2-policy-engine` [opus] | RBAC and ABAC using Cedar in-process. Usage modes per binding: relay, delegate, inject. | t6-org-members:contract | ☐ |
| T4 | `t4-access-proposals` | An agent requests access, a human approves in the console or CLI, and the grant is time-boxed. Kill switch. | t2-policy-engine:contract, t3-console-mvp | ☐ |
| N1 | `n1-notifications` | A notification inbox in the console plus Slack and email, driven by an outbox table and one rules matrix (which event goes to which channel and to whom). | t3-console-mvp | ☐ |
| M1 | `m1-remote-mcp` | Hub MCP (signs in as a person) and Agent MCP (signs in as an enrolled agent) over HTTP, with a switch per tool. No tool returns a stored secret value (decision H1-2). | t1-human-auth:contract | ☑ |
| T5 | `t5-honey-tokens` | Canary secrets that alert on any use and name the agent and its source. | n1-notifications:contract | ☐ |

## Phase 3: Delegation beyond HTTP

| # | Change | Usable outcome | Needs | Status |
|---|---|---|---|---|
| D1 | `d1-git-delegation` | The agent pushes to GitHub with no token in reach. | - | ☑ |
| D2 | `d2-aws-sts` [opus] | The agent uses the AWS CLI through short-lived STS credentials. Tested on Floci first. | t3-console-mvp | ◐ |
| D3 | `d3-db-relay` [opus] | Postgres relay with no password on the agent host (pgwire). | - | ◐ |
| D4 | `d4-workload-identity` | GitHub Actions and Kubernetes OIDC federation for CI and machine identities. | t1-human-auth:contract | ☑ |

## Phase 4: Deployable

| # | Change | Usable outcome | Needs | Status |
|---|---|---|---|---|
| P3 | `p3-agent-plugins` | Plugins or skills for the widely used agent frameworks on top of the existing local `locksmith-mcp` and `smith hook` (as `integrations/claude-code`, `codex` and `cursor` already do): add Gemini CLI, GitHub Copilot (VS Code agent mode and CLI), Windsurf and Cline, generated from `crates/smith-cli/src/agents.rs`, each with a live or recorded smoke test and a `just test <name>` recipe, plus a generic MCP setup for any other MCP client. | - | ◐ |
| P2 | `p2-packaging` | One-command self-host (compose and Helm), signed releases, `smith` installers. | - | ◐ |
| B1 | `b1-nestjs-api` | The control-plane API on NestJS 12 built the way Infisical builds its backend, with Rust kept for plaintext secrets, keys, proxies and audit signing; a strangler migration with contract tests, and oxlint, oxfmt and knip for all TypeScript (OC-8). Two owner gates first. | - | ☐ |
| P4 | `p4-sdks` | SDKs generated from OpenAPI, and the plugins switched to the remote Agent MCP where it helps. | m1-remote-mcp:contract | ☑ |

## Phase 5: Parity and beyond (ordered later, by demand)

Rotation and dynamic secrets (run in the gateway), syncs, the Terraform provider and k8s operator,
SAML and SCIM, passkeys (moved out of T1 to keep it small), local-only mode for solo developers.

## Product direction (not committed)

Certificates, KMS, Access Broker (brokered and recorded sessions to databases and servers) and
Security (scanning for exposed secrets) appear in the console mockup as direction only (owner
decision H1-4). No spec is written for any of them until Agent Gateway and Secret Management are in
use in the cloud, and each needs a research note first.

## Phase 6: GA hardening

External pentest, full adversarial suite, Windows parity (desktop, daemon and CLI tested on Windows; [#320](https://github.com/locksmith-hq/locksmith/issues/320)), Windows connector, docs and landing site.
