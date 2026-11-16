# Design: S1 Platform

Decisions marked **(confirm)** are recommended defaults the owner should confirm before work depends on them.

## D1. Trust boundaries
```
 human / CI / agent host (untrusted for secrets)         trusted plane
 ┌───────────────────────────────┐       ┌────────────────────────────────────────────────┐
 │ agent + smith + locksmith-mcp │──────▶│ Gateway(s)  ◀──wrapped keys/ciphertext── Control │
 │ (holds: agent token only)     │ HTTPS │ decrypt at use time, inject, redact, audit        │
 └───────────────────────────────┘       │ plane (Postgres): orgs, policy, approvals, audit  │
                                         └────────────────────────────────────────────────┘
```
Agent host holds only a short-lived, scoped, revocable **agent token**. All secret use goes through a gateway.

## D2. Key model: gateway-held keys, zero-knowledge control plane (confirm)
Infisical decrypts server-side with a KMS. M15 proposed pure client E2EE. A proxy must decrypt, so pure E2EE cannot support gateway injection. Chosen hybrid:
- Each **gateway** has an X25519 keypair (private key in the gateway's KMS/HSM/OS keystore, never in the control plane).
- A secret version is encrypted (XChaCha20-Poly1305 / AES-256-GCM, per-version DEK) and the DEK is wrapped to each gateway (and each human recovery key) authorised for that project/env.
- The control plane stores ciphertext + wraps + policy and **cannot decrypt**. Cloud-managed gateways run in a separate trust domain (separate account, no shared DB credentials) and are optional; customers can run their own gateways so Locksmith never sees plaintext.
- Humans read/write through the console: values are encrypted in the browser/desktop app to the project's gateway keys and the human's own key; "reveal" is a human-only, MFA-gated, audited action decrypting client-side.
- Trade-off recorded: server-side features that need plaintext (rotation, dynamic secrets, sync to third parties) run in the gateway, not the control plane.
This is also the product differentiator versus server-side-KMS designs.

## D3. Identities
Human (SSO/OIDC/email+passkey), **machine identity** (OIDC workload federation: GitHub Actions, K8s, AWS, GCP; no static secrets), **agent identity** (a machine identity with extra metadata: claimed client + model, verified process/host facts when available, per-agent policy and session TTL). Agents authenticate by workload federation or a short-lived token minted by a human or a CI job. Self-reported fields (model) are labelled unverified everywhere.

## D4. Policy (human/admin-owned, server-side)
RBAC (org, project, env) + ABAC conditions (agent identity, source, time, IP/network). Per secret binding: **usage mode** `relay` (default for agents), `delegate` (git/aws/db), `inject` (humans/CI only, never agents unless an admin explicitly permits). Allowed upstream hosts and paths per secret live here, never in the repository. This is M10e moved server-side: relay-only keys and policy-owned hosts become the default model, not an option.

## D5. Agent access flow
1. Agent connector authenticates; control plane returns the **grants** it may use (names, usage modes), no values.
2. Tool calls go to the gateway with the agent token; gateway checks policy, injects, forwards, **redacts the response**, audits.
3. **Access proposals**: if the agent lacks access it files a proposal (secret/host/scope, justification); an admin approves in the console, Slack or CLI; the grant is time-boxed. (Market parity with Agent Vault proposals.)
4. Kill switch: revoke an agent, session or secret; effective within seconds (gateways pull revocation by streaming + short token TTL).

## D6. Gateway
Rust, derived from `ls-proxy`: HTTP(S) credential proxy with network guard (no private/metadata ranges, resolve-then-dial), per-secret host and path allow-lists, placeholder substitution in header/path/query/body, response redaction, rate limits per agent, Git credential helper, AWS STS, Postgres/MySQL/Redis relay, request log. Stateless apart from key material and a revocation cache; horizontally scalable; self-hostable as one container.

## D7. Audit and detection
Append-only, hash-chained audit per org (reuse the audit-ledger design), exportable (S3, SIEM). Detections: **honey tokens** (canary secrets that alert on any use), anomaly flags (new host, burst, off-hours). These are open source, not enterprise-only.

## D8. Licence and pricing (confirm)
- **Licence: AGPL-3.0 for the server components** (control plane, gateway, console) so competitors cannot offer it as a closed SaaS; **Apache-2.0 for SDKs, CLI connector, plugins and protocol schemas** so adoption is frictionless. One repo, no `ee/` directory. (Alternative: MIT everywhere, weaker protection against hosted clones.)
- **Pricing hypothesis, to validate (the figures below are assumptions, not research):**
  Self-host: free, unlimited. Cloud Free: up to 5 humans, 3 projects. Cloud Team: per **human** seat (target well below Infisical's per-identity Pro at about $18 to $23), with machine and agent identities included under a fair-use cap, because per-identity billing punishes agent-heavy teams. Cloud Business/Enterprise: SSO (SAML/SCIM), audit retention, dedicated gateways, SLA, support. Revenue also from managed gateways (usage-based) and support contracts.
- Never-hostage (M13) remains: exports and self-hosting are always possible.

## D9. Stack (confirm)
Rust for control plane, gateway and anything touching plaintext (matches CLAUDE.md). Postgres (+ Redis optional for queues/cache; start with Postgres-only: `LISTEN/NOTIFY`, advisory locks, job table). Console: React + TypeScript (existing workspace), desktop: Tauri (existing). API: OpenAPI-first, generated TS/Python/Go SDKs. Deploy: Docker Compose, Helm, OpenTofu modules; OpenTelemetry built in.

## D10. What happens to existing work
- `smith` / `locksmith-mcp`: become the **agent connector**; keep local mode for solo users (offline vault) behind the same interfaces.
- Local daemon + agent-session policy (M10b/M10d): reused as the local-mode policy engine; the Sessions UI and source/model detection carry over to the console.
- M10e (relay-only keys, policy-owned hosts, network guard): implemented once, in `ls-proxy`, shared by local mode and the gateway; policy file becomes one policy source among others.
- M15 (E2EE sync): superseded by D2 for shared secrets; its invites, safety numbers and org-policy-as-code ideas survive as console features.
- M13 licensing: reworked from per-device offline licences to org plans (D8); offline verification kept for self-host paid support keys, if any.

## D11. Build vs outsource
Rule: **build what defines the product and touches plaintext; reuse or rent everything else.** Each choice must be swappable behind an interface and licence-compatible with D8 (AGPL server may use MIT/Apache/BSD dependencies; check any AGPL, SSPL or BSL component before adopting). Candidates below are starting points from general knowledge, **not evaluated or version-checked**.

| Area | Build in-house (core) | Outsource / reuse (candidates) |
|---|---|---|
| Key model, secret storage format, per-version DEK wrapping | yes | crypto libraries only (RustCrypto, rustls) |
| Gateway: injection, redaction, network guard, allow-lists | yes (from `ls-proxy`) | HTTP stack (hyper, rustls); optionally Envoy as a later data plane |
| Agent identity, grants, access proposals, sessions | yes | none |
| Audit hash chain | yes (reuse audit-ledger) | export via Vector/OTel to SIEMs |
| Key custody for gateway private keys | interface | AWS/GCP/Azure KMS, HSM, HashiCorp Vault Transit |
| Human auth, SSO, SCIM | thin adapter | Ory Kratos/Hydra, Keycloak, WorkOS (hosted SSO/SCIM), passkeys via WebAuthn libs |
| Machine/workload identity | verifier code | OIDC federation (GitHub, K8s, cloud), SPIFFE/SPIRE |
| Authorisation engine | policy semantics | Cedar or OPA as the evaluator, or an in-process Rust engine (decide by spike) |
| Billing, metering, invoices | plans table | Stripe (+ Lago or OpenMeter for usage) |
| Email, chat notifications | templates | Postmark/Resend, Slack and Teams APIs |
| Secret scanning | policy hooks | gitleaks / trufflehog rules |
| Rotation and dynamic secrets connectors | connector interface | upstream provider SDKs; community connector repo |
| Database, queues, cache | schema | managed Postgres (RDS, Neon, Cloud SQL); Postgres-only queues first |
| Hosting and deploy | Helm/OpenTofu modules | Kubernetes on AWS/GCP, Fly.io for early cloud |
| Observability, status, docs | dashboards | OpenTelemetry, Grafana stack, Instatus, Docusaurus/Mintlify |
| Compliance | controls | Vanta/Drata for SOC2; external pen tests |

## D12. Risks
Large scope: mitigate with thin vertical slices (tasks). Operating a hosted multi-tenant security product (SOC2, incident response, key custody) is a business risk, not only an engineering one. Replacing the exploit-resistance of "separate machine" with software controls on cloud gateways needs independent security review before GA. Pricing and licence choices have commercial consequences that need an owner decision.
