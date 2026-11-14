# Design: M13 Subscription and Licensing

## Decisions

### D1. Why signed leases, not online checks
Developers work offline, on planes, in air-gapped environments. A 30-day signed lease with 14 days
of grace means no connectivity requirement in day-to-day use. Revocation latency is up to 30 days,
which is acceptable for licensing (not security). Enterprise can shorten it.

### D2. Server data minimisation
The license server stores the account email, Stripe customer id, plan, device public keys, device
display names (user-editable), and last refresh time. It never stores anything about secrets,
projects, key names or repos. The device activation payload is `{device_pubkey, os, arch,
app_version}`.

### D3. Entitlement checks are local and cheap
`Entitlements::from_license(&verified)` is cached in the daemon and re-evaluated on refresh. Gates
are checked at feature entry points. Unit tests per tier cover every gate, generated from a single
`features.toml` that also renders the pricing table in `apps/web`, so the website and the product
cannot drift.

### D4. Stripe as the source of truth for billing
The license server does not compute proration or tax. It maps Stripe subscription state to tier and
seats on each webhook (idempotent by event id), and periodically reconciles with the Stripe API.

### D5. Stack
axum, sqlx (Postgres), `stripe-rust` (async-stripe), `jsonwebtoken`-free custom Ed25519 signing via
`ed25519-dalek`. The signing key lives in KMS. The server holds only the public key set plus
KMS-sign permission.

## Risks / Trade-offs
- License cracking: the binaries are open to patching. That is an accepted risk. The value for
  Team/Enterprise lives in server-side features (sync, SSO, central audit), so cracked Pro mostly
  hurts Pro revenue.
