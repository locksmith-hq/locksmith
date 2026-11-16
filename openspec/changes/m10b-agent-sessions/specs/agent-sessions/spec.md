# Spec Delta

## Purpose

Lets an agent start bounded sessions itself, and blocks it automatically on suspicious activity.

## ADDED Requirements

### Requirement: Policy-bound agent sessions
The daemon SHALL grant an agent-started session only when project, environment, scopes and TTL are within the human-owned policy; otherwise it SHALL require human approval.

#### Scenario: Outside policy
- **WHEN** the agent asks for a production session the policy does not allow
- **THEN** no lease is created and a human approval is requested

### Requirement: Automatic block
On a strong suspicious signal, or a weak-signal score over the threshold, the daemon SHALL revoke the session, stop its process tree, refuse new agent sessions for the project, and audit the reason.

#### Scenario: Secret read attempt
- **WHEN** a session's output contains a vault secret
- **THEN** the lease is revoked, the project enters cooldown, and a BLOCK event with the reason is audited
