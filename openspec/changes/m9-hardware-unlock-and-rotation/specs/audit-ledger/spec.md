# Spec Delta

## ADDED Requirements

### Requirement: External anchors
The daemon SHALL write signed checkpoints of the ledger head to the operating system log at every session end and every 1000 events, and optionally to a git notes ref.

#### Scenario: Truncated ledger detected
- **WHEN** an attacker deletes the last 50 ledger events and recomputes nothing
- **THEN** `smith audit verify` reports that the ledger head is behind the latest anchor
