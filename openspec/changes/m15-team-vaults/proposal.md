# Proposal: M15 Team Vaults

> **Reframed by [s1-secrets-platform](../s1-secrets-platform/proposal.md) (D2, D10):** shared secrets use gateway-held keys so a proxy can inject them; the invite, safety-number and org-policy ideas below carry over to the console.

## Why

Teams share credentials today through Slack, 1Password or `.env` files in private repos. Each agent
user on a team needs the same delegated access, and security leads need one place to set policy and
see audit. That is the Team tier's value (docs/product/subscription-plans.md).

## What Changes

- **Shared vaults, end-to-end encrypted:** each user has an X25519 identity key (in their vault). A
  shared vault has its own vault key, wrapped to each member's public key. The sync server stores
  only ciphertext and wraps.
- **Sync server** (`services/sync-server`, Rust axum, Postgres plus object storage): an append-only
  encrypted change log per vault, member and wrap management, conflict-free last-writer-wins per
  secret version.
- **Invites and verification:** `smith team invite email`. The invitee's public key is verified by
  comparing a short fingerprint out of band (safety numbers), to prevent server key substitution.
- **Removal:** removing a member triggers automatic vault key rotation (M9 state machine) and lists
  the upstream secrets the member could read, with "rotate upstream" guidance and connector-driven
  rotation where available.
- **Org policy as code:** a signed `locksmith.policy.toml` (signed by an admin key) distributed by
  the sync server. It covers allowed agents, max lease TTL, Mode C forbidden in prod,
  biometric_strict environments, AWS/HTTP allowlists and update channel pinning.
- **Central audit:** members' daemons stream audit events (metadata only, already value-free)
  encrypted to the org audit key. The admin console in the desktop app and web shows a merged
  timeline. Enterprise adds SIEM export.
- **SSO (OIDC)** for Team sign-in to the license and sync server. SAML and SCIM are Enterprise.

## Usable outcome

A team lead creates a shared "payments" vault and invites four engineers. Everyone's agents use
Stripe via `lsk_` tokens under one org policy, and the lead sees all agent access in one audit view.

## Capabilities

### New Capabilities
- `team-vaults`: End-to-end encrypted shared vaults, membership and sync.
- `org-policy`: Organisation-wide signed policy and central audit.

### Modified Capabilities

## Out of scope

- SAML, SCIM and SIEM connectors (Enterprise, M16+ backlog). Self-hosted sync ships as an image
  only.

## Impact

`services/sync-server`, `ls-vault` (shared vault type), `ls-crypto` (X25519 wraps), `ls-broker`
(policy merge), desktop and web admin screens.
