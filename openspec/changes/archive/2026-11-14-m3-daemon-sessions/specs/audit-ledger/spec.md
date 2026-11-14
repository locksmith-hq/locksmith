# Spec Delta

## Purpose

Records every credential decision in a ledger whose past entries cannot be silently altered, even by someone who later compromises the machine.

## ADDED Requirements

### Requirement: Every decision recorded
The daemon SHALL append an audit event for every access, create, rotate, revoke and blocked decision, including caller identity, session, target secret identifier, policy rule and outcome, and SHALL never record secret values.

#### Scenario: Access recorded
- **WHEN** `smith run` injects two secrets
- **THEN** two ACCESS events with the secret identifiers are appended

### Requirement: Tamper evidence
Each event SHALL be chained to its predecessor by hash and authenticated with a forward-secure key, and `smith audit verify` SHALL detect any modification, deletion or reordering of stored events.

#### Scenario: Edited event
- **WHEN** an attacker modifies a stored event
- **THEN** `smith audit verify` reports the first broken sequence number and exits 1

### Requirement: Forward security
Key material available to the running daemon SHALL NOT allow forging or recomputing authentication for earlier events.

#### Scenario: Full verification needs recovery phrase
- **WHEN** the user runs `smith audit verify --full` and supplies the recovery phrase
- **THEN** every event's authentication is checked from the root key
