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

## REMOVED Requirements

### Requirement: Values are write-only through the API
**Reason**: the API no longer accepts a plaintext value at all (decision H1-1); its guarantees are restated in `secret-write-console`.
**Migration**: clients seal with `ls-envelope` (native or WebAssembly) and post ciphertext.
