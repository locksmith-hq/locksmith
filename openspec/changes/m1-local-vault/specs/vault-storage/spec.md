# Spec Delta

## Purpose

Persists the vault so that everything at rest, including metadata such as key names, is encrypted, versioned and safe against partial writes.

## ADDED Requirements

### Requirement: Fully encrypted storage at rest
The vault database SHALL be page-encrypted with a key derived from the vault key, so key names, project names and environment names are not readable without unlocking.

#### Scenario: Offline inspection
- **WHEN** an attacker copies the vault files and searches them for a known key name
- **THEN** the key name is not found in any file

### Requirement: Tamper-evident header
The unlock header SHALL be integrity-protected so that modification of any wrap or parameter is detected after unlock.

#### Scenario: Header edit
- **WHEN** a byte in a stored KDF parameter is altered
- **THEN** unlock fails or reports header tampering, and no secret is returned

### Requirement: Crash-safe writes
Every vault mutation SHALL be atomic: after a crash at any point the vault opens in either the pre- or post-mutation state.

#### Scenario: Kill during write
- **WHEN** the process is killed while adding a secret
- **THEN** the next open succeeds and the secret is either fully present or absent

### Requirement: Restrictive file permissions
Vault files SHALL be created with mode 0600 inside a 0700 directory owned by the user, and Locksmith SHALL refuse to open a vault whose files are accessible to other users.

#### Scenario: World-readable vault
- **WHEN** the vault file is mode 0644
- **THEN** commands exit with code 1 and doctor check `vault.perms` reports fail with remediation

### Requirement: Schema versioning
The vault SHALL record a schema version and SHALL migrate forward automatically, after writing a backup copy, when a newer Locksmith opens an older vault.

#### Scenario: Forward migration
- **WHEN** a vault at schema N is opened by a build supporting N+1
- **THEN** a timestamped backup is written first and the vault is migrated to N+1
