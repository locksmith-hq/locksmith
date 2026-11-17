# Spec Delta

## Purpose
Each org has one append-only audit history that is hash-chained and periodically signed, so an operator can prove that no event was edited, removed, reordered or inserted, and can keep a copy outside the database.

## ADDED Requirements

### Requirement: Per-org append-only hash chain
Every audit event SHALL belong to exactly one org and carry a per-org sequence number starting at 1 with no gaps, the hash of the previous event in that org (all zeros for the first), and its own hash over a deterministic encoding of all its fields. Application roles SHALL be able to insert events but not update or delete them, and each org SHALL see only its own events.

#### Scenario: Concurrent appends stay linear
- **WHEN** 50 events are appended concurrently for one org
- **THEN** their sequence numbers are exactly 1 to 50 and each event's previous hash equals the hash of the event before it

#### Scenario: App role cannot rewrite history
- **WHEN** the application role runs UPDATE or DELETE on an audit event
- **THEN** the database refuses the statement

#### Scenario: Cross-org isolation
- **WHEN** org B lists audit events through the API
- **THEN** none of org A's events are returned

### Requirement: Events never contain secret values
Audit events SHALL store identifiers, hosts, modes, statuses and outcomes only, and never a secret value, a request or response header value, a request body or a URL query string.

#### Scenario: Canary absent from the ledger and its export
- **WHEN** a relay call carrying the canary secret runs and the ledger is exported
- **THEN** `just leak-scan` finds the canary in neither the `audit_events` table nor the export directory

### Requirement: Signed checkpoints
The system SHALL periodically sign a checkpoint containing the org, the latest sequence number, that event's hash and the time, using a signing key held in the KMS (OpenBao transit locally). The public key SHALL be available to verifiers without access to the signing key.

#### Scenario: Checkpoint after threshold
- **WHEN** an org reaches the configured event threshold
- **THEN** a checkpoint for that org's latest event exists and its signature verifies under the published public key

### Requirement: Verification detects tampering
`just audit-verify` SHALL check every org's chain and checkpoints and exit non-zero, naming the org and the first broken sequence number, if any event was edited, deleted, reordered or inserted, if a checkpoint signature is invalid, or if the chain ends before the latest checkpoint. On an intact ledger it SHALL exit zero.

#### Scenario: Edited event
- **WHEN** the database owner changes one field of a stored event
- **THEN** verify fails at that event's sequence number

#### Scenario: Deleted or reordered event
- **WHEN** the database owner deletes one event, or swaps the sequence numbers of two events
- **THEN** verify fails at the first affected sequence number

#### Scenario: Tail truncation behind a checkpoint
- **WHEN** the database owner deletes the newest events, including ones a checkpoint covers
- **THEN** verify reports that the chain ends before the latest checkpoint

#### Scenario: Intact ledger
- **WHEN** no event has been changed
- **THEN** verify exits zero and reports the number of events and checkpoints checked per org

### Requirement: Export to a file sink
`locksmith-audit export` SHALL write each org's events, in sequence order, together with its checkpoints, to a file sink directory. It SHALL resume from where the last export stopped without writing an event twice. Verify SHALL accept an export directory and apply the same checks offline, using only the public key.

#### Scenario: Incremental export verifies offline
- **WHEN** events are exported, more events are appended, and the export runs again
- **THEN** the directory holds every event exactly once in order, and `locksmith-audit verify --dir` on it exits zero without database or KMS access

#### Scenario: Tampered export detected
- **WHEN** one line of an exported file is edited
- **THEN** offline verify fails at that event's sequence number

### Requirement: Operators can see the ledger
The control-plane API SHALL list an org's audit events (paged, newest first) and report the latest checkpoint and the latest verify result. The web console and the desktop app SHALL show the same list and status.

#### Scenario: Console shows events and status
- **WHEN** an operator opens the audit page after a relay call
- **THEN** the page lists that call's events and shows the latest checkpoint sequence number and verify result
