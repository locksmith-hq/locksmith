# Proposal: N1 notifications

## Why
Today a person learns what an agent did only by opening the console and reading the audit ledger. T4 (access requests) and T5 (honey tokens) both need to tell a human *now*: "agent X asks for access", "a canary secret was used". Without a notification path each would invent its own. N1 builds one: an outbox table fed by a few trusted event kinds, a single rules matrix saying which event goes to which channel and to whom, an in-console inbox, and Slack and email delivery.

## What Changes
- **Outbox.** A `notification_outbox` table, written in the same transaction as the event that causes it. A worker drains it with retry and backoff; delivery never blocks or fails the originating request.
- **Rules matrix.** One table `notification_rules(org_id, event_kind, channel, audience)`: for each event kind, per channel (`inbox`, `email`, `slack`), who gets it (`owners`, `admins`, `all_members`, or a named user). Defaults seeded per org; editable by owner or admin.
- **Inbox.** A per-user `notifications` list (unread count, mark read, mark all read) with `GET /v1/notifications`, `POST /v1/notifications/{id}/read`.
- **Email.** SMTP delivery through a configured relay (Mailpit locally); the SMTP password is a server secret in `secrecy` types.
- **Slack.** An incoming-webhook URL per org, stored encrypted as a secret-grade value (the URL is a bearer credential), never returned by the API after it is set.
- **Contract for T5 and T4.** `n1-notifications:contract` is group 1: the event-kind enum, the payload schema, and a `notify(event)` function stub with fixtures, so T5 can emit `honey.triggered` before delivery exists.
- **Payloads carry no secrets.** A notification names the agent, the event kind, the object (secret name, never value), time and a console deep link. A redaction check runs over every payload before it is stored.
- **Audit.** `notification.rule_changed`, `notification.channel_configured` and `notification.delivery_failed` are ledger events (no webhook URL, no SMTP password, no addresses beyond a count).
- **Console and desktop.** A bell with unread count and an inbox page, a Settings > Notifications page (rules matrix, Slack webhook, email on/off), in `apps/web` and `apps/desktop`.

## Out of scope
- Mobile push, SMS, PagerDuty, Teams and other channels; per-user quiet hours or digests.
- Emitting T4 and T5 events (those changes call `notify`); N1 only wires the audit kinds listed in design.md.
- Sending T6's invite email as part of N1 delivery is included only as one more event kind (`member.invited`) once T6 is on main; if T6 is not merged, the kind is declared and unused.
- Per-recipient channel preferences beyond the org rules matrix.

## Depends on
`t3-console-mvp` (pages, shared client, fixtures). Group 1 to 4 do not need it; groups 5 and 6 stack on it. T6 members are read when present, falling back to the org owner.

## Usable outcome
When an agent does a watched thing (denied grant use, secret revoked, relay anomaly), the right people see it in the console inbox within seconds and, if the org turned it on, in Slack and email, with no secret values in any message; an owner changes who gets what from one settings page.
