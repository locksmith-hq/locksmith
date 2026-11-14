# session-leases Specification

## Purpose
Lets a user authorize an agent once for a bounded time, project and set of operations, and take that authorization back instantly.

## Requirements

### Requirement: Session start binds to a process tree
`smith session start -- <cmd>` SHALL unlock the vault if needed, launch the command, and create a lease bound to that process and its descendants, for a project, environment, scope set and expiry.

#### Scenario: Descendant allowed
- **WHEN** a process started by the agent runs `smith run -- npm test`
- **THEN** it runs without a passphrase prompt

#### Scenario: Outside process denied
- **WHEN** `smith run` is invoked from a terminal that is not part of the session tree
- **THEN** it does not use the session's lease

### Requirement: Lease expiry
Leases SHALL expire at their expiry time, and operations after expiry SHALL fail with exit code 4.

#### Scenario: Expired lease
- **WHEN** a lease with a 1-minute TTL is used after 61 seconds
- **THEN** the operation fails with exit code 4

### Requirement: Revocation
`smith revoke <id>` and `smith revoke --all` SHALL invalidate leases so that no operation starting after revoke returns is authorized under them.

#### Scenario: Revoke
- **WHEN** the user revokes a session while the agent is idle
- **THEN** the agent's next credential operation fails with exit code 4 and a REVOKE event is audited

### Requirement: Session visibility
`smith status` SHALL list active leases with id, root command, project, environment, scopes, created time and expiry.

#### Scenario: Status
- **WHEN** two sessions are active
- **THEN** `smith status --json` lists both with their fields
