# Proposal: M13 Subscription and Licensing

## Why

Locksmith needs revenue to sustain a security product. It must earn it without becoming one more
thing that can lock developers out of their own credentials or phone home with sensitive data. The
plan is in [docs/product/subscription-plans.md](../../../docs/product/subscription-plans.md):
Free / Pro / Team / Enterprise, offline-verifiable licenses, Stripe billing, and the never-hostage
rule.

## What Changes

- **License format:** a signed license document (Ed25519, compact JWS-like CBOR) with
  `{license_id, account_id, tier, seats, features[], device_limit, issued_at, expires_at, grace_days}`.
  Verified offline by `ls-license` against an embedded public key set that supports rotation.
- **Device activation:** `smith license activate` (browser device-code flow) binds a device key
  (Ed25519, stored in the vault) to the account. The server returns a **lease license** valid for
  30 days with 14 days of grace, refreshed silently in the background.
- **Entitlements:** one `Entitlements` API checked by the CLI, daemon, desktop app and MCP server.
  Feature gates follow the tier table. Limits (projects, upstreams, devices) are enforced on
  *creation*, never on use of existing items.
- **Never-hostage:** on expiry, revocation, a missing network or a bad signature, the tier drops to
  Free. Existing paid-feature configuration becomes read-only (e.g. DB relay listeners do not start)
  and is never deleted. Unlock, export and all Free features keep working.
- **Trial:** `smith license trial` gives 14 days of Pro, once per account.
- **License server** (`services/license-server`, Rust axum, Postgres): accounts (email magic link and
  GitHub OAuth), Stripe webhooks, device activations, lease issuance, revocation list, Team seat
  assignment, telemetry ingest route (M11, separated).
- **Billing:** Stripe Checkout (subscriptions), Customer Portal, Stripe Tax, webhooks
  (`checkout.session.completed`, `customer.subscription.updated|deleted`, `invoice.payment_failed`),
  and dunning per the pricing doc.
- **Account portal:** pages in `apps/web` (sign in, plan, devices, seats, invoices link, license
  download for offline/air-gapped use), calling license-server APIs.
- **Enterprise:** offline license files (no activation server) and a self-hostable license server
  image.

## Usable outcome

A user upgrades from the CLI (`smith upgrade` opens Checkout) or from the website. Pro features
unlock within seconds. If they cancel, they return to Free with every secret intact.

## Capabilities

### New Capabilities
- `licensing`: License verification, device activation, entitlements and graceful downgrade.
- `billing`: Plans, checkout, subscription lifecycle and dunning.
- `account-portal`: Web self-service for accounts, devices and seats.

### Modified Capabilities

## Out of scope

- Usage-based pricing. Marketplace billing (AWS Marketplace) is in the backlog.

## Impact

New `crates/ls-license`, `services/license-server`, `apps/web` account section, `infra/`
(Postgres on Neon or RDS, Fly.io or ECS for the service), Stripe account and products.
