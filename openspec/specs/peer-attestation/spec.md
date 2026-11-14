# peer-attestation Specification

## Purpose
Ensures the daemon only serves genuine Locksmith components acting for an authorized session, and rejects every other local process.

## Requirements

### Requirement: Kernel-verified caller identity
The daemon SHALL identify each caller using kernel-provided identity (audit token on macOS, peer credentials with a process file descriptor on Linux) rather than a caller-supplied claim.

#### Scenario: Spoofed claim
- **WHEN** a client claims to be `smith` in its request but is a different binary
- **THEN** the daemon classifies it as unknown and rejects credential operations

### Requirement: Binary authenticity
The daemon SHALL serve credential operations only to callers whose executable matches a signed or hash-pinned Locksmith binary.

#### Scenario: Rogue same-user client
- **WHEN** a Python script running as the same user connects to the socket and requests an operation
- **THEN** the request is rejected and a BLOCKED audit event records the caller's executable path

### Requirement: Unknown callers limited
Callers that fail attestation SHALL only be able to query daemon version and health.

#### Scenario: Health from unknown caller
- **WHEN** an unknown caller sends `ping`
- **THEN** it receives a version and status reply with no vault metadata
