# Tasks

## 1. Secure Enclave

- [ ] 1.1 Spike (design D1): a signed app-bundled daemon creates and uses a biometryCurrentSet SE key. Record the result in design.md. Verify: a spike demo video and notes in the PR.
- [ ] 1.2 HW wrap creation and unlock via ECDH and HKDF, plus `smith vault biometric enable|disable`. Verify: a unit test with a software P-256 mock, and a manual Touch ID test on 2 Macs.
- [ ] 1.3 Enrollment-change fallback and re-provisioning. Verify: a manual checklist (add a fingerprint, unlock, check the message, check re-enroll).
- [ ] 1.4 `biometric_strict` environments with the step-up prompt text. Verify: e2e with a mocked authenticator, plus a manual prompt screenshot.

## 2. Rotation

- [ ] 2.1 State machine and batch migration (design D2). Verify: unit tests per state transition.
- [ ] 2.2 Crash-injection harness: 200 random kills. Verify: `cargo test -p ls-vault --test rotation_crash -- --ignored` passes.

## 3. Audit anchors

- [ ] 3.1 Anchor key, OS log writer (os_log / journald) and git notes writer. `smith audit verify` cross-checks. Verify: e2e truncation detection.

## 4. Diagnostics

- [ ] 4.1 Doctor checks `hw.secure_enclave`, `hw.enrollment`, `vault.rotation_state`. Verify: snapshots.
