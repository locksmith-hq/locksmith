# Design: N1 notifications

## Context
The control plane writes a hash-chained audit ledger (`services/control-plane/src/audit.rs`, `append(conn, org_id, event)`) inside per-request transactions bound to an org (RLS, `current_org_id()`). Mailpit already runs in compose (profile `auth`, SMTP 1025, API 8025). `reqwest` is a control-plane dependency. N1 adds a delivery layer next to the ledger without touching the ledger's chain.

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **Transactional outbox in Postgres**: `notification_outbox` row inserted in the event's transaction; a worker polls with `FOR UPDATE SKIP LOCKED`. | Direct send inside the request (couples latency and failure to Slack/SMTP); a broker such as NATS or Redis (new service; Postgres is the only required datastore). | microservices.io transactional outbox pattern; PostgreSQL docs on `SKIP LOCKED` queueing. |
| 2 | **Notifiable kinds are a closed enum** (`NotifyKind`), mapped from audit kinds, not arbitrary strings; T4 and T5 add variants. | Notifying on every audit event (noise, volume); free-form kinds (rules matrix cannot validate). | Roadmap T4/T5 rows; AGENTS.md "start small". |
| 3 | **One rules matrix** `notification_rules(org_id, kind, channel, audience)` with seeded defaults (inbox to owners). Audience resolves through T6 memberships when present, else the org's owner. | Per-user preferences (second matrix, out of scope); hard-coded routing. | Roadmap N1 row ("one rules matrix"). |
| 4 | **Slack by incoming webhook**, one per org. The URL is a bearer credential, so it is stored envelope-encrypted like other secret-grade values and write-only over the API. | Slack OAuth app (install flow, token refresh, much larger); logging the URL. | Slack docs "Sending messages using incoming webhooks"; AGENTS.md security rules. |
| 5 | **Email via `lettre` over SMTP** to a configured relay (Mailpit locally). | Calling an email API (vendor lock-in, new secret type); spawning `sendmail`. | `lettre` is the maintained Rust SMTP crate (check release date at apply). |
| 6 | **Payload is allow-listed fields only** (kind, actor id/name, object name, time, link) and passes `ls-redact` before insert. | Serializing the audit event body; trusting callers. | `ls-redact` in-repo; security rule "never serialize a plaintext secret". |
| 7 | **Retries: 5 attempts, backoff 10s x 4^n**, then `failed` with one ledger event. | Infinite retry (poison rows); no retry. | Standard bounded-retry practice; tested with a fake endpoint. |
| 8 | **Inbox is rows in `notifications(user_id, outbox_id, read_at)`**, created by the same worker step as other channels, so inbox works with no external service. | Computing the inbox from the ledger on read (no read state, no per-user routing). | Local-first principle. |
| 9 | **Contract first**: enum, payload schema, `notify()` stub and fixtures land in group 1 so T5 stacks on `n1-notifications:contract`. | T5 waiting for delivery code. | `openspec/config.yaml` tasks rule. |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| `lettre` | MIT | pin at apply (latest 0.11.x) | verify at apply | SMTP client with rustls | permissive; control-plane is a server component anyway |
| `wiremock` (dev only) | MIT/Apache-2.0 | pin at apply | verify at apply | fake Slack endpoint in tests, if not already a workspace dev-dependency | n/a |
| Mailpit `axllent/mailpit:v1.21.8` | MIT | already in compose | already pinned | local SMTP sink and API for tests | n/a |

Built in-house: the outbox worker and rules resolution (about 300 lines). Searched first: Rust outbox crates and Apprise/Novu; they bring a separate service or a generic queue that would sit outside our RLS tenant boundary, and the logic here is a Postgres query. Verify the crate versions and dates at apply and record them in progress.md.

## Data model
- `notification_rules(org_id, kind, channel, audience, audience_user_id null, PRIMARY KEY (org_id, kind, channel))`; forced RLS by org.
- `notification_outbox(id uuid v7, org_id, kind, payload jsonb, channel, recipient_user_id null, state pending|sent|failed, attempts, next_attempt_at, last_error_code, created_at)`; forced RLS; indexed on `(state, next_attempt_at)`.
- `notifications(id, org_id, user_id, kind, payload jsonb, created_at, read_at)`; RLS by org and `user_id = current_user_id()` for reads.
- `notification_channels(org_id PRIMARY KEY, slack_webhook_ciphertext bytea null, smtp_enabled bool)`; ciphertext wrapped with the org key, never selected into a response type.
- Worker runs as a control-plane background task with a `login`-style role setting to scan across orgs under RLS (same pattern as the audit checkpoint job, migration 0010); no `BYPASSRLS`.

## API (contract group)
`GET /v1/notifications?unread=`, `POST /v1/notifications/{id}/read`, `POST /v1/notifications/read-all`, `GET/PUT /v1/notification-rules`, `GET/PUT /v1/notification-channels` (Slack URL and SMTP enable are write-only; reads return booleans), `POST /v1/notification-channels/test` (sends a fixed test message). Rules and channels require owner or admin.

## Risks
- A webhook URL in a log line leaks a credential: delivery code never formats the URL; errors map to fixed slugs. A leak-scan canary covers it.
- SSRF through a user-supplied webhook URL: accept only `https://hooks.slack.com/services/...` (documented allow-list, tests for `http`, IP literals, other hosts) and never follow redirects.
- Volume spikes: the worker batches and caps sends per org per minute (default 60); overflow collapses into one "N more events" item.

## Open questions
None blocking. Assumed and recorded: Slack incoming webhooks only; SMTP relay configured by server env vars, not per org.

## How an agent debugs this
- DB: `just psql`, `select state, count(*) from notification_outbox group by 1;` and `notifications`; postgres MCP read-only.
- Mail: Mailpit UI on :8025 or `curl localhost:8025/api/v1/messages`.
- Logs and traces: control-plane logs `notify.enqueue`, `notify.deliver` with kind, channel and outcome only; OTel spans of the same names in the local stack.
- Ledger: `just audit-verify` and `GET /v1/audit` for `notification.*`.
- Tests: `cargo nextest run -p ls-control-plane notifications`; `just leak-scan`.
