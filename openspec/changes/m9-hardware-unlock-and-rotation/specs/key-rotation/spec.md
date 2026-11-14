# Spec Delta

## Purpose

Lets users replace the vault key at any time without data loss, even if the machine crashes mid-rotation.

## ADDED Requirements

### Requirement: Vault key rotation
`smith vault rotate-key` SHALL replace the vault key, rewrap every data key and all unlock wraps, and re-encrypt the database pages, after which the old vault key decrypts nothing.

#### Scenario: Completed rotation
- **WHEN** rotation completes
- **THEN** all secrets read correctly and the stored key version has incremented

### Requirement: Crash-safe rotation
A rotation interrupted at any point SHALL resume or complete on the next daemon start without data loss, and all secrets SHALL remain readable throughout.

#### Scenario: Crash injection
- **WHEN** the daemon is killed at a random point during rotation, 200 times
- **THEN** each restart resumes and every secret reads correctly at the end
