# Tasks (phased; each phase ends in something usable)

## Phase 0 : Decisions and foundations
- [ ] 0.1 D2, D8 licence and D9 confirmed. Still open: pricing validation, product name and domain, cloud vs self-host split.
- [ ] 0.2 Threat model for the platform (gateway compromise, control-plane compromise, malicious agent, malicious member, tenant isolation) in docs/; independent review scheduled.
- [ ] 0.3 Repo layout: `services/control-plane`, `services/gateway`, `apps/console`, `infra/compose`, `infra/helm`; licence files per D8; `scripts/tree-check.sh` updated.

- [ ] 0.4 Build-vs-outsource spikes per D11 (auth, authorisation engine, billing/metering, KMS custody): one-day spike each, choose, record licence, version and exit plan.

## Phase 1 : Single-tenant core (self-host first)
- [ ] 1.1 Control plane: orgs, users (email+passkey, OIDC), projects, environments, secrets and versions stored as ciphertext + wraps; audit chain. Verify: API tests, sqlx migrations, no plaintext columns (schema test).
- [ ] 1.2 Gateway: HTTP credential proxy extracted from `ls-proxy` (relay, redaction, network guard, host/path allow-lists from policy); key registration with the control plane. Verify: canary extraction suite (m10e 4.1) passes against the gateway.
- [ ] 1.3 Agent identities and tokens; `smith login`, connector mode; `locksmith_*` MCP tools talk to the platform. Verify: the Langfuse trace fetch works with the secret never on the agent host (host has no secret in memory, disk or environment; test asserts via process scan).
- [ ] 1.4 Console MVP: secrets, projects, members, agents, sessions (source and model), audit. Verify: Vitest + Playwright smoke.
- [ ] 1.5 `docker compose up` single-node install and docs.

## Phase 2 : Teams
- [ ] 2.1 RBAC/ABAC, groups, invites, SSO (OIDC), machine identity federation (GitHub Actions, K8s, AWS).
- [ ] 2.2 Access proposals and approvals (console, CLI, Slack), time-boxed grants.
- [ ] 2.3 Revocation streaming, kill switch, per-agent rate limits, honey tokens.
- [ ] 2.4 Git, AWS (STS), database delegation in the gateway.

## Phase 3 : Cloud
- [ ] 3.1 Multi-tenant hosting, managed gateways in a separate trust domain, billing (Stripe), plans per D8.
- [ ] 3.2 Helm chart, OpenTofu modules, backups, OpenTelemetry, status page, SOC2 readiness plan.
- [ ] 3.3 SDKs (TS, Python, Go), Terraform provider, Kubernetes operator, CI integrations.

## Phase 4 : Depth
- [ ] 4.1 Secret rotation and dynamic secrets in the gateway, SIEM streaming, SAML/SCIM, audit retention tiers.
