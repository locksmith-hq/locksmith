# Spec Delta

## Purpose

Brings Locksmith's core guarantees (attested IPC, hardware unlock, containment) to Windows workstations.

## ADDED Requirements

### Requirement: Windows peer attestation
On Windows the daemon SHALL accept credential operations only from callers whose executable has a valid Authenticode signature from the Locksmith signer, over a pipe restricted to the current user and rejecting remote clients.

#### Scenario: Unsigned client
- **WHEN** an unsigned executable connects to the pipe
- **THEN** credential operations are rejected and audited

### Requirement: Windows Hello unlock
On Windows with a TPM 2.0, users SHALL be able to unlock with Windows Hello, with the vault key unwrapped inside the TPM boundary.

#### Scenario: Hello unlock
- **WHEN** the user starts a session with Hello enrolled
- **THEN** a Windows Hello prompt appears and the session starts on success

### Requirement: Job object containment
Agent sessions on Windows SHALL run in a job object that terminates all processes when the session is revoked with kill.

#### Scenario: Revoke kill
- **WHEN** a session with background processes is revoked with kill
- **THEN** no session process remains after 5 seconds
