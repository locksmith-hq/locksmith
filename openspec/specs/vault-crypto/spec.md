# vault-crypto Specification

## Purpose
Defines how Locksmith derives, wraps and uses keys so that secrets at rest stay confidential and tamper-evident.

## Requirements

### Requirement: Independent vault key
The vault SHALL be encrypted under a randomly generated 256-bit vault key that is never stored in plaintext and is wrapped independently by each unlock method.

#### Scenario: Passphrase change keeps data keys
- **WHEN** the user changes the passphrase
- **THEN** only the passphrase wrap is rewritten and no secret ciphertext or wrapped data key changes

### Requirement: Memory-hard passphrase derivation
Passphrase unlock SHALL use Argon2id with at least 64 MiB memory, 3 iterations, parallelism 4 and a 32-byte random salt, and SHALL store the parameters with the wrap.

#### Scenario: Parameters recorded
- **WHEN** a vault is created
- **THEN** the passphrase wrap records algorithm argon2id and its memory, iterations, parallelism and salt

### Requirement: Fresh data key per secret version
Each stored secret version SHALL be encrypted with its own random 256-bit data key, and that key SHALL be wrapped by the vault key with AES-256-GCM and a random 96-bit nonce.

#### Scenario: Two versions, two keys
- **WHEN** the user sets a secret twice
- **THEN** the two stored versions have different wrapped data keys and nonces

### Requirement: Ciphertext bound to identity
Decryption SHALL fail when a ciphertext or wrapped data key is moved to a different secret, version or environment, because the associated data binds those immutable identifiers.

#### Scenario: Transplant attack
- **WHEN** an attacker copies an encrypted payload from a development secret row into a production secret row
- **THEN** reading the production secret fails with an integrity error and an audit event of type BLOCKED is recorded once auditing exists

#### Scenario: Rename is safe
- **WHEN** the user renames a key
- **THEN** its value still decrypts

### Requirement: No plaintext secret in diagnostics
Key and secret types SHALL NOT be printable through debug or display formatting, logs or serialization.

#### Scenario: Log scan
- **WHEN** the test suite runs with trace logging enabled and canary secrets in the vault
- **THEN** no encoding of any canary appears in captured logs
