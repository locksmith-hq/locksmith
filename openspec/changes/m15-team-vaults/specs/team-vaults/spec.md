# Spec Delta

## Purpose

Lets teams share credentials for agent use while the sync service never sees plaintext and membership changes are cryptographically enforced.

## ADDED Requirements

### Requirement: End-to-end encrypted sharing
Shared vault contents SHALL be encrypted so that only current members' devices can decrypt them, and the sync service SHALL store only ciphertext and wrapped keys.

#### Scenario: Server breach
- **WHEN** an attacker obtains the full sync database and object storage
- **THEN** no secret value or key name can be recovered from it

### Requirement: Member key verification
Adding a member SHALL require the admin to verify the member's key fingerprint or explicitly accept it as unverified, and a later key change SHALL produce a blocking warning.

#### Scenario: Substituted key
- **WHEN** the server presents a different public key for an existing member
- **THEN** clients refuse to wrap to it and warn the admin

### Requirement: Removal rotates access
Removing a member SHALL rotate the shared vault key and SHALL list the upstream credentials the member could read, with rotation guidance.

#### Scenario: Offboarding
- **WHEN** an admin removes a member
- **THEN** the removed member's devices cannot decrypt new versions, and the admin sees the list of secrets to rotate upstream

### Requirement: Forged changes rejected
Clients SHALL reject vault changes not signed by a current member.

#### Scenario: Server-injected change
- **WHEN** the sync server injects an unsigned change
- **THEN** clients reject it and report an integrity error
