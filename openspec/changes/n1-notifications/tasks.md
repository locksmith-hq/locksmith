# Tasks: N1 notifications

## 1. Contract [sonnet]
- [ ] 1.1 Add `NotifyKind`, the allow-listed payload type, notification, rule and channel types to the OpenAPI schema (utoipa), regenerate `packages/control-plane-client`; routes return `501`.
- [ ] 1.2 Add a `notify(conn, org_id, kind, payload)` stub in `services/control-plane/src/notify.rs` (inserts nothing yet) so T5 can call it, and fixtures in `apps/web/src/api/fixtures.ts` (inbox of 3, rules matrix, channel state).
- [ ] 1.3 Verify: `cargo nextest run -p ls-control-plane openapi` and `npm test --workspace packages/control-plane-client`.

## 2. Schema and tenancy [sonnet]
- [ ] 2.1 Migration (next free number; check `ls services/control-plane/migrations`): `notification_rules`, `notification_outbox`, `notifications`, `notification_channels` with forced RLS and grants as in design.md; seed default rules on org creation.
- [ ] 2.2 Cover all four tables in `ls-tenant-lint`; a migration test proves isolation and the defaults.
- [ ] 2.3 Verify: `cargo nextest run -p ls-control-plane tenancy` and `cargo nextest run -p ls-tenant-lint`.

## 3. Enqueue and rules [sonnet]
- [ ] 3.1 Implement `notify()`: allow-list payload, `ls-redact` check, resolve recipients from the rules matrix (T6 memberships when the table exists, else owner), insert outbox and inbox rows in the caller's transaction.
- [ ] 3.2 Wire the first kinds from existing audit paths: `grant.denied`, `secret.revoked`, `agent.revoked`; a rolled-back transaction leaves no row.
- [ ] 3.3 `GET/PUT /v1/notification-rules` (owner or admin) with `notification.rule_changed` ledger event.
- [ ] 3.4 Verify: `cargo nextest run -p ls-control-plane notify_enqueue notify_rules` (default routing, rule change, member `403`, rollback, secret canary refused).

## 4. Delivery worker [opus]
- [ ] 4.1 Background worker: `FOR UPDATE SKIP LOCKED` poll, bounded retries with backoff, per-org rate cap with an overflow summary item, fixed error slugs, `notification.delivery_failed` ledger event.
- [ ] 4.2 Email via `lettre` to the configured SMTP relay; add Mailpit to the default compose profile for N1 tests.
- [ ] 4.3 Slack incoming webhook delivery: URL allow-list (`https://hooks.slack.com/services/`), no redirects, URL envelope-encrypted and write-only; `PUT /v1/notification-channels`, `POST .../test`.
- [ ] 4.4 Add cases to `tests/adversarial/cases`: webhook URL to an internal host refused, URL absent from every log and response, payload carrying a secret canary refused.
- [ ] 4.5 Verify: `cargo nextest run -p ls-control-plane notify_worker notify_channels`, `bash tests/adversarial/run.sh`, `just leak-scan`, `just audit-verify`.

## 5. Inbox API [sonnet]
- [ ] 5.1 `GET /v1/notifications`, `POST /v1/notifications/{id}/read` and `read-all`, scoped to the calling user.
- [ ] 5.2 Verify: `cargo nextest run -p ls-control-plane notifications_inbox` (own items only, cross-org empty, unread count).

## 6. Web console [sonnet]
- [ ] 6.1 Bell with unread count in the top bar and an inbox page with mark read and mark all read, deep links from each item.
- [ ] 6.2 Settings > Notifications page: rules matrix editor, Slack webhook (write-only field, shows configured state and a test button), email on/off; buttons hidden by role and errors shown.
- [ ] 6.3 Verify: `npm test --workspace apps/web` (fixtures cover empty, `403`, delivery-failed banner).

## 7. Desktop surface [sonnet]
- [ ] 7.1 Desktop bell, inbox view and notifications settings in `apps/desktop/src` using the shared client; Vitest tests including `403`.
- [ ] 7.2 Verify: `npm test --workspace apps/desktop` and `just apps-build`.

## 8. Local verification [sonnet]
- [ ] 8.1 `just notify-smoke` and `tests/e2e/tests/notifications.rs`: start Mailpit and a fake Slack endpoint, deny a grant, assert the inbox item, the Mailpit message and the Slack call, none containing a secret value, and that a Slack outage does not fail the denial.
- [ ] 8.2 `just up`, `just notify-smoke`, `just apps-build`, then `just quick`.
