# Spec Delta

## Purpose

Lets an agent start bounded sessions itself, and blocks it automatically on suspicious activity.

## ADDED Requirements

### Requirement: Policy-bound agent sessions
The daemon SHALL grant an agent-started session only when project, environment, scopes and TTL are within the human-owned policy; otherwise it SHALL require human approval.

#### Scenario: Outside policy
- **WHEN** the agent asks for a production session the policy does not allow
- **THEN** no lease is created and a human approval is requested

#### Scenario: Agent-started session covers the agent's commands
- **WHEN** the agent starts an in-policy session through the MCP server and then runs `smith run` from its own shell
- **THEN** the lease is rooted at the agent process that launched the MCP server (identified by the kernel), the command is authorized, and the agent's parent (the terminal) is not

#### Scenario: Agent root cannot be established
- **WHEN** the MCP server's parent cannot be identified, is pid 1, belongs to another user, or is not the same process (pid reuse)
- **THEN** no lease is created and the refusal is audited

#### Scenario: Agent starts a second session
- **WHEN** the agent starts another in-policy session while its earlier agent-started session is active
- **THEN** the earlier lease is revoked and audited as replaced, and the new one is granted under the same policy

### Requirement: Automatic block
On a strong suspicious signal, or a weak-signal score over the threshold, the daemon SHALL revoke the session, stop its process tree, refuse new agent sessions for the project, and audit the reason.

#### Scenario: Secret read attempt
- **WHEN** a session's output contains a vault secret
- **THEN** the lease is revoked, the project enters cooldown, and a BLOCK event with the reason is audited
