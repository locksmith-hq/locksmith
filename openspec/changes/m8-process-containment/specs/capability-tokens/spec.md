# Spec Delta

## Purpose

Limits what any single process in an agent session can do to the specific operations it was granted, so code the agent runs cannot reuse the whole session.

## ADDED Requirements

### Requirement: Untrusted descendants excluded
Processes running under package installation or build entry points SHALL NOT be authorized by the session lease unless the project policy grants that command a capability.

#### Scenario: Hostile postinstall
- **WHEN** an npm postinstall script inside the session attempts a Git push, an HTTP relay call and a DB relay connection
- **THEN** all three are rejected and BLOCKED events identify the script process

### Requirement: Operation-scoped capabilities
A capability SHALL authorize exactly one operation type and target, and SHALL be rejected for any other operation.

#### Scenario: Reuse for another target
- **WHEN** a process holding a `git:push` capability for repo A uses it for repo B
- **THEN** the request is rejected

### Requirement: Capability lifetime
Capabilities SHALL expire on first use when single-use, after at most 60 seconds otherwise, and immediately on session revoke.

#### Scenario: Expired capability
- **WHEN** a capability is presented 61 seconds after issue
- **THEN** it is rejected
