# Tasks

## 1. License core (`ls-license`)

- [ ] 1.1 License document format, Ed25519 verification, key-set rotation, and `features.toml` → entitlements codegen (design D3). Verify: unit tests per tier for every gate.
- [ ] 1.2 Wire the gates into CLI, daemon, MCP and proxies with creation-only limits. Verify: the never-hostage e2e suite (expired, revoked, missing, bad signature → Free, export and run work).

## 2. License server (`services/license-server`)

- [ ] 2.1 axum service, sqlx migrations, accounts (magic link via Postmark/SES, GitHub OAuth), sessions. Verify: integration tests with testcontainers Postgres.
- [ ] 2.2 Device activation (device code flow), lease issuance via KMS signing, refresh, revocation list. Verify: e2e `smith license activate` against a local server.
- [ ] 2.3 Stripe products and prices as code (a `stripe` fixtures file), Checkout session creation, Customer Portal links, idempotent webhooks, daily reconciliation. Verify: Stripe CLI `stripe trigger` tests in CI (test mode).
- [ ] 2.4 Team seats and member invites. Verify: integration tests.
- [ ] 2.5 Deploy with `infra/` (Fly.io or ECS), health checks, a self-host image for Enterprise. Verify: staging deploy with smoke tests.

## 3. Client UX

- [ ] 3.1 `smith license status|activate|deactivate|trial|refresh`, `smith upgrade <plan>`, doctor checks `license.valid`, `license.refresh`. Verify: e2e against staging.

## 4. Account portal (`apps/web`)

- [ ] 4.1 Account pages (sign in, plan, devices, seats, invoices, offline license) using `packages/ui`, and a pricing page generated from `features.toml`. Verify: Playwright e2e against staging.

## 5. Milestone acceptance

- [ ] 5.1 End-to-end purchase in Stripe test mode: CLI upgrade, then a Pro feature works, cancel, wait past grace (time-travel test clock), then Free with export working. Verify: the recorded run is attached to the PR.
