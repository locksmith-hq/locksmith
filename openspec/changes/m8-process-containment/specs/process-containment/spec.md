# Spec Delta

## Purpose

Keeps track of every process an agent session starts so that revoking the session reliably stops all of them.

## ADDED Requirements

### Requirement: Complete tree tracking
Locksmith SHALL track every process started within a session, including processes that call setsid or double-fork, using the strongest containment backend available on the platform.

#### Scenario: Daemonised child
- **WHEN** an agent starts a background server with `nohup ... &` and `setsid`
- **THEN** `smith status --processes` lists it under the session

### Requirement: Revoke terminates the tree
`smith revoke --kill` SHALL close relays, invalidate capabilities, and terminate all tracked processes, escalating to forced termination after 3 seconds.

#### Scenario: Revoke under load
- **WHEN** revoke runs while concurrent Git, HTTP and AWS operations are in flight
- **THEN** no operation is authorized after revoke returns and no session process remains after 5 seconds

### Requirement: Escaped process reporting
Processes that could not be terminated or escaped tracking SHALL be reported to the user by PID and command, never silently ignored.

#### Scenario: Unkillable process
- **WHEN** a session process survives forced termination
- **THEN** revoke exits 1 and lists the surviving process
