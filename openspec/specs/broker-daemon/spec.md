# broker-daemon Specification

## Purpose
Provides the single long-lived process that holds unlocked key material and performs credential operations for verified local callers.

## Requirements

### Requirement: Single per-user daemon
Locksmith SHALL run at most one daemon per user, reachable only through a socket inside a directory accessible only to that user.

#### Scenario: Second instance
- **WHEN** a second `locksmithd` starts for the same user
- **THEN** it exits with a message naming the running instance

### Requirement: No plaintext egress over IPC
The daemon protocol SHALL NOT include any operation that returns a plaintext secret value to a client, except environment injection into a process the daemon itself spawns.

#### Scenario: Protocol audit
- **WHEN** the protocol schema is inspected by the test suite
- **THEN** no response type contains a secret-value field

### Requirement: Fail closed on restart
After a daemon restart the vault SHALL be locked and all leases SHALL be invalid.

#### Scenario: Crash during session
- **WHEN** the daemon is killed and restarted during an active session
- **THEN** the next operation in that session fails with exit code 4 until the user starts a new session

### Requirement: Automatic lock
The daemon SHALL lock the vault, dropping key material, after the configured idle timeout and on screen lock or system sleep.

#### Scenario: Screen lock
- **WHEN** the user locks the screen
- **THEN** the vault is locked within 2 seconds and active leases are suspended
