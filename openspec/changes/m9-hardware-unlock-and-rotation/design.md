# Design: M9 Hardware Unlock, Rotation, Anchors

## Decisions

### D1. Spike first (2 days)
Before building, prove that a Developer ID–signed `locksmithd` inside an app bundle, launched by a
LaunchAgent, can create and use a Secure Enclave key with `.biometryCurrentSet`. The usual failure is
`errSecMissingEntitlement` without an embedded provisioning profile. The outcome is recorded here,
and the packaging is changed in M0's release pipeline if needed.

### D2. Rotation state machine
States are persisted in `meta.rotation = {state, from_version, to_version, cursor}`:
`IDLE → PREPARED (new wraps written alongside the old) → DUAL_ACTIVE (writes use new, reads either) →
MIGRATING (batches of 500 DEK re-wraps per transaction, cursor advances) → FINALIZING (SQLCipher
PRAGMA rekey to the new db_key, delete the old wraps, zeroize) → IDLE`.
Recovery on start: resume from the persisted state. The rekey is the only non-batched step. It is
protected by a pre-rekey file copy that is removed after success.

### D3. Anchors
Each checkpoint is signed with a per-vault Ed25519 anchor key (wrapped by VK) so anchors can be
verified without the recovery phrase. Anchors in the OS log are append-only from the user's point of
view, and the git notes give off-machine durability when pushed.

## Risks / Trade-offs
- The SE provisioning-profile requirement may force distribution as an app bundle on macOS. That is
  acceptable and aligns with the M14 desktop app.
