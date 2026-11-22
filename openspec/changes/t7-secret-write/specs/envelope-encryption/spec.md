# Spec Delta

## Purpose
The control plane stores only ciphertext and never sees a secret value or a plaintext data key; only the gateway can open them.

## MODIFIED Requirements

### Requirement: DEK wrapped to a gateway key in a KMS
The DEK SHALL be wrapped either by a KMS key through a `KeyWrapper` trait (purpose `dek-wrap`, the existing format) or, for versions sealed by a client, by HPKE to the environment's seal public key (a distinct `alg_id`). The stored row SHALL record the key id of whichever wrapped it.

#### Scenario: Wrap and unwrap with the gateway credential
- **WHEN** a KMS-wrapped version is written and the gateway test credential unwraps its DEK
- **THEN** the value decrypts to the submitted bytes

#### Scenario: HPKE-wrapped version opens at the gateway
- **WHEN** a version sealed to the environment public key is stored and the gateway decrypts it
- **THEN** the value equals the sealed bytes, and opening with a different org, secret, version, purpose or key id fails with no plaintext in the error

### Requirement: The control plane cannot decrypt
The control plane SHALL NOT hold a credential or key that can unwrap a DEK or open a version, and for sealed writes SHALL never hold the plaintext or the DEK, even in memory.

#### Scenario: Decrypt is refused
- **WHEN** the control plane's credential asks the KMS to unwrap a stored wrapped DEK or a wrapped seal private key
- **THEN** the KMS denies the request

#### Scenario: Zeroized after write
- **WHEN** the write path completes or fails
- **THEN** any buffer the control plane held for the request is zeroized (verified by a unit test on the secret types, which have no Debug, Display or Clone)

#### Scenario: Private seal key never reaches the control plane
- **WHEN** an environment seal key is provisioned
- **THEN** the control plane stores only the public key and the KMS-wrapped private key, and a test that inspects its database and logs finds no private key bytes

### Requirement: Values are write-only through the API
Secret version creation SHALL NOT accept a plaintext value or a plaintext DEK (decision H1-1); it accepts only a sealed ciphertext and wrapped DEK (see `secret-write-console`) and returns only version metadata. No endpoint, log line or trace attribute SHALL return or contain a value, a DEK, a wrapped DEK or a wrapped seal private key, including read, list and `seal-key` routes.

#### Scenario: Create a version
- **WHEN** a client posts a sealed version to a secret
- **THEN** the response is `201` with the version number and `version_count` increases, and the body contains no value

#### Scenario: Read and list routes hold no key material
- **WHEN** a client reads or lists versions or requests the seal key
- **THEN** no response body, log line or trace attribute contains a value, a DEK, a wrapped DEK or a wrapped seal private key

#### Scenario: No canary anywhere
- **WHEN** a canary value is written through the sealed route
- **THEN** `just leak-scan` over Postgres, Loki and Tempo finds no encoding of it

#### Scenario: Cross-org isolation
- **WHEN** org B requests versions of org A's secret
- **THEN** the response is `404`
