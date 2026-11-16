# Infisical: competitor inspection (2026-11-16)

Sources: GitHub API reads of github.com/Infisical (marked [gh]); https://infisical.com/pricing ([price]);
Infisical docs pages (named). Items marked UNVERIFIED were not confirmed. Re-check prices before quoting externally.

## Licence split [gh: infisical/LICENSE, backend/src/ee/LICENSE.md]
- Root is MIT Expat **except anything under `ee/`**, which is the "Infisical Enterprise License".
  Production use needs a paid subscription; redistribution is forbidden. Self-hosted EE validates a
  `LICENSE_KEY` against Infisical's licence server [gh: docs/self-hosting/ee.mdx].
- Verified in `backend/src/ee/services` (2026-11-16): `agent-vault*` (12 services: access-bundle,
  delegation, oauth, proxy, session, session-log, skill, variable, ...), `gateway-v2`, `gateway-pool`,
  `relay`, `honey-token`, plus `pam-*`, `dynamic-secret`, `secret-rotation-v2`, `saml-config`, `scim`,
  `ldap-config`, `access-approval-*`, `audit-log-stream`, `pit`, `external-kms`, `hsm`, `kmip`,
  `secret-scanning-v2`, `secret-sync`, `pki-acme/scep/est`.
- **Conclusion: every agent, gateway, approval, honey-token, rotation and SSO feature is commercial.**

## Repos [gh]
| Repo | Purpose | Lang | Licence | Stars |
|---|---|---|---|---|
| infisical | platform | TS | MIT + `ee/` | ~30.5k |
| agent-vault | standalone agent credential proxy | Go | MIT + `ee/` template | ~2.5k |
| cli | CLI | Go | MIT + `ee/` template | ~100 |
| infisical-mcp-server | MCP wrapper over the API (no brokering) | JS | Apache-2.0 | ~80 |
| SDKs (node, python, go, rust, dotnet), kubernetes-operator, terraform-provider, secrets-action, csi-provider, agent-injector, kmip, cert-manager issuer | delivery | various | not checked | small |

The standalone **agent-vault README says not to use it for any use case** and points to the paid
in-platform Agent Vault (verified 2026-11-16).

## Architecture
- Backend: TypeScript, Fastify 5, Knex + Postgres, BullMQ + Redis [gh: backend/package.json]. Compose: app + Postgres 14 + Redis. Also Helm, Swarm, CloudFormation, FIPS image.
- Encryption: 256-bit root key (env var or HSM) → internal KMS root → per-org/per-project data keys, AES-256-GCM. External KMS optional. **Server-side decrypt; not zero-knowledge; root key in server memory** [doc: internals/security].
- Gateway: outbound SSH reverse tunnel to a relay, SSH certs issued by Infisical; mTLS direct mode self-host only; 3-minute heartbeat; pools [doc: gateways/overview].
- Machine identities: universal auth, token, JWT, OIDC, AWS/Azure/GCP/AliCloud/OCI, Kubernetes, LDAP, TLS cert, SPIFFE.

## Pricing [price]
- Secrets, per identity per month: Free $0 (5 identities, 3 envs, 10 syncs); Pro $20 annual / $23 monthly; Advanced $40 / $46 (dynamic secrets, gateways, rotation); Enterprise custom (SCIM, approvals, KMIP, external KMS).
- PAM Pro $20/user/month. PKI free up to 10 certs.
- **Agent Vault: per brokered request, first 5,000/month free, then $1 per 10,000.**

## Agent Vault (their AI-agent story)
- Forward proxy via `HTTPS_PROXY`, TLS MITM with a CA installed by `infisical agent-vault run`.
- Per request: live session check → host matched to a service in the session's access bundle → credential injected (header or placeholder in header/path/query). OAuth refresh with one retry.
- Sessions are time-bound grants; method/path rules per service; unmatched hosts forwarded or denied by policy.
- Service types: HTTP, MCP servers, databases, SSH. Launched April 2026 as research preview.
- Common-proxy mode sends session tokens to the proxy over plain HTTP [doc: agent-vault/how-it-works].
- "MCP tool filtering" appears on the pricing page but not in the how-it-works doc: UNVERIFIED.

## Gaps Locksmith can beat (each tied to evidence above)
1. Agent access is paid and in `ee/`; the only OSS version is deprecated → ours is fully open (AGPL server).
2. Metered per-request billing for agent calls → no per-request fee; price by human seat.
3. Server-side decrypt with root key in memory → zero-knowledge control plane, decrypt only in the gateway.
4. Heavy self-host (Node + Postgres + Redis + licence server + gateway + relay) → Rust binaries + Postgres only.
5. Generic proxy + CA install; no coding-agent hooks documented → native Claude Code/Cursor/Codex hooks, MCP, blocked-command explanations.
6. Session tokens over plain HTTP in common-proxy mode → mTLS or unix socket between agent and gateway.
7. EE depends on Infisical's licence server → never-hostage rule.

## What we may reuse
- MIT code outside `ee/` (with notices) and the Apache-2.0 MCP server. **Never copy anything under `ee/`.**
- Ideas (not code): access bundles, sessions, placeholder substitution, per-agent proxy, OAuth refresh-retry, session logs, honey tokens, reverse-tunnel relay.
