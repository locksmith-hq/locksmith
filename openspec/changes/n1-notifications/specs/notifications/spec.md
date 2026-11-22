# Spec Delta

## Purpose
Tell the right people about security-relevant events through an inbox, email and Slack, driven by one outbox and one rules matrix.

## ADDED Requirements

### Requirement: Events enter an outbox transactionally
A notifiable event SHALL insert its outbox rows in the same transaction as the change that caused it, and delivery SHALL run afterwards in a worker. A delivery failure SHALL NOT fail or roll back the originating request.

#### Scenario: Delivery failure does not block the request
- **WHEN** the Slack endpoint is down while an agent grant is denied
- **THEN** the denial response is unchanged and the outbox row is retried with backoff

#### Scenario: Rolled-back event leaves no notification
- **WHEN** the transaction that would emit an event rolls back
- **THEN** no outbox row exists

### Requirement: One rules matrix decides recipients
For each org, event kind and channel the system SHALL send to the audience set in `notification_rules` (`owners`, `admins`, `all_members` or one user), using seeded defaults until changed. Only an org owner or admin SHALL change rules.

#### Scenario: Default routing
- **WHEN** a new org's agent is denied a grant and rules are untouched
- **THEN** org owners get an inbox item and no email or Slack message

#### Scenario: Rule change takes effect
- **WHEN** an admin sets `grant.denied` / `slack` to `admins`
- **THEN** the next such event produces a Slack delivery and a `notification.rule_changed` ledger event

#### Scenario: Member cannot edit rules
- **WHEN** a plain member calls the rules endpoint
- **THEN** the response is `403`

### Requirement: Inbox is per user and tenant-isolated
Each recipient SHALL see only their own notifications, in their org, with unread state they can mark read.

#### Scenario: Mark read
- **WHEN** a user marks a notification read
- **THEN** their unread count drops by one and no other user's count changes

#### Scenario: Cross-org isolation
- **WHEN** a user of org A requests notifications while bound to org B
- **THEN** none of org A's items are returned

### Requirement: Payloads never carry secret values
A notification payload SHALL contain only the event kind, actor and object identifiers or names, time and a console link. The system SHALL run a redaction check over every payload before storing it and SHALL refuse to enqueue one that fails.

#### Scenario: Secret value in a payload is refused
- **WHEN** a payload contains a string matching a stored secret's canary value
- **THEN** it is not enqueued and a `notification.delivery_failed` event records the reason without the value

### Requirement: Channel credentials are write-only
The Slack webhook URL and SMTP password SHALL be stored as secret-grade values, SHALL never be returned, logged or audited after being set, and the API SHALL show only whether each is configured.

#### Scenario: Webhook is not readable back
- **WHEN** an admin sets a Slack webhook and then reads the channel settings
- **THEN** the response says `configured: true` and contains no part of the URL

### Requirement: Delivery is bounded and retried
The worker SHALL retry transient failures with exponential backoff up to a fixed attempt limit, then mark the row failed and raise one ledger event; it SHALL deliver each row at most once on success.

#### Scenario: Retry then fail
- **WHEN** an SMTP server rejects every attempt
- **THEN** after the limit the row is `failed`, one `notification.delivery_failed` event exists, and no further attempts run

#### Scenario: No duplicate on success
- **WHEN** two workers poll the same pending row
- **THEN** exactly one delivers it (row lock with `SKIP LOCKED`)
