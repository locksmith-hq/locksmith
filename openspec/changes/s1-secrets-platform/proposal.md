# Proposal: S1 Locksmith Platform (open-source team secrets and agent-access SaaS)

## Why

The product mindset changes from "a vault on the developer's machine that guards the agent" to
**secrets never live on the machine where an agent runs**. A secret on the same host as the agent
can be extracted (live test: a canary leaked through reversed/spaced/ROT13 output; same-user
processes cannot be fully isolated). The pattern the market converged on, and that Infisical's Agent
Vault and TRM's Gatehouse implement, is a credential proxy on a different trust boundary that
attaches the secret to requests to approved destinations. Teams also need one place to share,
rotate, approve and audit secrets across people, services and agents.

Infisical (MIT core, `ee/` directory under a commercial licence; Pro about $18 to $23 per identity
per month, free tier of 5 identities) is the reference. Its agent-access features (Agent Vault,
honey tokens, dynamic secrets, PAM, SAML, SCIM, approval workflows) live in `ee/` and need a paid
licence to run in production. Locksmith's opening: **everything open source in one repo, agent access
as the core product, and a lower, simpler price**.

## What Changes

A new top-level product line, `Locksmith Platform`, built from the Locksmith components that already exist:

1. **Control plane** (Rust, axum, Postgres): orgs, projects, environments, secrets with versions,
   humans, machine identities, **agent identities**, policy, approvals, audit, billing hooks.
2. **Gateway** (Rust, from `ls-proxy`): the credential proxy and the only place secret values are
   decrypted at use time. Runs as Locksmith Cloud gateways or **self-hosted in the customer's network**.
   Handles HTTP (placeholder and header injection with response redaction), Git, AWS (STS), databases.
3. **Agent connector** (`smith`, `locksmith-mcp`, plugins): holds no secrets. It authenticates the
   agent to the platform, lists what the agent may use, requests access, and points tools at the
   gateway. The local daemon becomes optional offline cache and UX, not the trust anchor.
4. **Web console and desktop app** (React/Tauri): teams, secrets, sessions with agent source and
   model, approvals, audit, policy.
5. **Open source, self-hostable, cloud-hosted**: one `docker compose up` / Helm chart; hosted cloud sells convenience, scale and support, not locked features.

## Usable outcome (first slice)

A team signs up on the cloud or self-hosts, adds an org and a project, stores a Langfuse key in the
console, creates an agent identity, and an agent on a laptop or CI calls the Langfuse API through
the gateway with `smith`/MCP. The secret never reaches the laptop. The console shows who (human and
agent, with source and model), what, when, and lets a human approve or revoke.

## Principles

- **Agents never hold secrets.** No `run`-style injection into agent-controlled processes for agent identities; relay, delegation, short-lived scoped credentials only.
- **The control plane cannot read secrets** (see design D2): values are encrypted to gateway keys.
- **Open core is the whole product.** No hidden `ee/` directory; one licence.
- **Never hostage**: export and self-host always available.
- **Honest limits** documented per feature (what a relay does and does not prevent).

## Out of scope for S1 (later slices)

Certificates/PKI, privileged access (PAM) sessions and recording, secret scanning at scale, a
marketplace of integrations beyond the first 10, mobile apps.

## Impact

New: `services/control-plane`, `services/gateway`, `apps/console`, `packages/sdk-*`, `infra/helm`,
`infra/compose`. Reused: `ls-proxy`, `ls-redact`, `ls-crypto`, `ls-vault` format, `ls-ipc` types,
`locksmith-mcp`, `smith-cli`, desktop app. Reframed: M15 team vaults (see D2), M13 licensing (see D8),
M10b/M10e agent-policy (becomes server-side policy), the local daemon (becomes a client).
