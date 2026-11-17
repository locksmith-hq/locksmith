# envelope-encryption Specification

## Purpose
Secret values are stored only as envelope-encrypted ciphertext whose data keys the control plane cannot unwrap.

## Requirements

### Requirement: Per-version envelope encryption
Each secret version SHALL be encrypted under a fresh random 256-bit DEK using AES-256-GCM. The stored blob SHALL carry the A0-7 header `magic(2) ‖ format_ver(1) ‖ alg_id(1) ‖ key_id(16) ‖ nonce ‖ ciphertext ‖ tag`, and the AEAD SHALL authenticate the header and `org_id ‖ secret_id ‖ version ‖ purpose`.

#### Scenario: Round trip
- **WHEN** a version is sealed and then opened with the same DEK and binding
- **THEN** the original bytes are returned

#### Scenario: Wrong binding fails
- **WHEN** a ciphertext is opened with a different org, secret, version or purpose, or with any header byte altered
- **THEN** opening fails with an error that contains no plaintext

#### Scenario: Known answers
- **WHEN** the fixed-key test vectors are sealed
- **THEN** the output matches the committed vectors byte for byte

#### Scenario: DEKs are not reused
- **WHEN** two versions of one secret are written
- **THEN** their wrapped DEKs and nonces differ

### Requirement: DEK wrapped to a gateway key in a KMS
The DEK SHALL be wrapped by a KMS key through a `KeyWrapper` trait, using the same header format with purpose `dek-wrap`. The local implementation SHALL use OpenBao transit; the stored row SHALL record the gateway `key_id`.

#### Scenario: Wrap and unwrap with the gateway credential
- **WHEN** a version is written and the gateway test credential unwraps its DEK
- **THEN** the value decrypts to the submitted bytes

### Requirement: The control plane cannot decrypt
The control plane's KMS credential SHALL permit wrapping only. After a write, the control plane SHALL hold neither the plaintext nor the DEK in memory beyond the request, and SHALL zeroize both.

#### Scenario: Decrypt is refused
- **WHEN** the control plane's credential asks the KMS to unwrap a stored wrapped DEK
- **THEN** the KMS denies the request

#### Scenario: Zeroized after write
- **WHEN** the write path completes or fails
- **THEN** plaintext and DEK buffers are zeroized (verified by a unit test on the secret types, which have no Debug, Display or Clone)

### Requirement: Values are write-only through the API
Secret version creation SHALL accept a value and return only version metadata. No endpoint, log line or trace attribute SHALL return or contain a value, a DEK or a wrapped DEK.

#### Scenario: Create a version
- **WHEN** a client posts a value to a secret
- **THEN** the response is `201` with the version number and `version_count` increases, and the body contains no value

#### Scenario: No canary anywhere
- **WHEN** a canary value is written
- **THEN** `just leak-scan` over Postgres, Loki and Tempo finds no encoding of it

#### Scenario: Cross-org isolation
- **WHEN** org B requests versions of org A's secret
- **THEN** the response is `404`
