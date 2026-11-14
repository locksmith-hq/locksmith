# Spec Delta

## Purpose

Lets users unlock Locksmith with device biometrics bound to secure hardware, and require fresh biometric approval for sensitive environments.

## ADDED Requirements

### Requirement: Biometric unlock
On supported hardware the user SHALL be able to enroll biometric unlock, after which unlocking requires a successful biometric check performed by the secure hardware, without the passphrase.

#### Scenario: Touch ID session
- **WHEN** the user runs `smith session start` with biometric unlock enrolled
- **THEN** a Touch ID prompt appears and the session starts after success

### Requirement: Enrollment change invalidates biometric unlock
If the set of enrolled biometrics changes, biometric unlock SHALL stop working until the user unlocks with the passphrase, after which it SHALL be re-provisioned.

#### Scenario: New fingerprint added
- **WHEN** a fingerprint is added in system settings
- **THEN** the next unlock asks for the passphrase and explains why, then re-enables Touch ID

### Requirement: Biometric step-up per environment
Environments marked biometric-strict SHALL require a fresh biometric approval for each access, even inside an active session.

#### Scenario: Production access
- **WHEN** an agent's operation needs a secret from a biometric-strict production environment
- **THEN** the user sees a Touch ID prompt naming the project, environment, key and requesting command
