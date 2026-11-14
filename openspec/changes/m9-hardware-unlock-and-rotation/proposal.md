# Proposal: M9 Hardware Unlock, Key Rotation and Audit Anchors

## Why

Typing a passphrase for every session pushes users toward long TTLs, which is worse for security.
v5 §3 specifies Secure Enclave and TPM unlock with enrollment invalidation, §9.2 a crash-safe vault
key rotation, and §9.4 external audit anchors. M9 delivers these on macOS. Windows TPM comes in M16,
and Linux stays on passphrase, with optional TPM2 in M16.

## What Changes

- macOS Secure Enclave wrap: a P-256 key with `.biometryCurrentSet` and `WhenUnlockedThisDeviceOnly`.
  ECDH with an ephemeral key, then HKDF → HWK, then AES-GCM(VK). If enrollment changes, the user
  falls back to the passphrase and the key is re-provisioned.
- Per-environment `biometric_strict`: every access to that environment needs a fresh Touch ID,
  even inside a lease.
- VK rotation: `smith vault rotate-key`, the five-state crash-safe state machine from v5 §9.2 (wraps
  rewritten, DEKs re-wrapped in batches, SQLCipher rekey last).
- Audit anchors: at session end and every 1000 events, a checkpoint `{seq, head_hash}` is written to
  the macOS unified log or journald, and optionally to a `refs/notes/locksmith-audit` note in a
  user-chosen repo. `smith audit verify` cross-checks the anchors.
- Doctor checks: `hw.secure_enclave`, `hw.enrollment`, `vault.rotation_state`.

## Usable outcome

`smith session start` asks for Touch ID instead of a passphrase. Production environments can require
a Touch ID per access. The vault key can be rotated safely at any time.

## Capabilities

### New Capabilities
- `hardware-unlock`: Biometric, hardware-bound unlock and per-environment step-up.
- `key-rotation`: Crash-safe rotation of the vault key.

### Modified Capabilities
- `audit-ledger`: Adds external anchors. These are additive requirements, delivered as ADDED in this
  delta because the base spec is archived from M3.

## Out of scope

- Windows Hello and TPM, and Linux TPM2 (M16).

## Impact

`ls-platform::macos` (`security-framework`, `objc2-local-authentication`). Signing requirement: the
daemon ships inside `Locksmith.app` with the keychain-access-groups entitlement and a provisioning
profile (docs/v6-review.md §3).
