# Tasks

## 1. Daemon and protocol

- [ ] 1.1 `ls-ipc`: framed CBOR protocol with versioning, request/response enums, and a schema test asserting no secret-value field in any response. Verify: `cargo test -p ls-ipc`.
- [ ] 1.2 `locksmithd`: socket in the 0700 runtime dir, single-instance lock, unlock/lock state, fail-closed restart, `smith daemon install|uninstall|status`. Verify: e2e for the second-instance message and lock-after-restart.
- [ ] 1.3 Auto-lock on idle, screen lock and sleep (design D5). Verify: an integration test fakes the D-Bus signal on Linux, and a manual macOS checklist covers the rest.

## 2. Attestation (`ls-platform`)

- [ ] 2.1 macOS audit token plus code requirement check. Verify: a test binary signed with an ad-hoc identity is classified unknown, and the release-signed `smith` is accepted (CI with a test signing cert).
- [ ] 2.2 Linux peercred, pidfd, starttime and exe-hash manifest. Verify: a test where a copy of `smith` with one flipped byte is rejected.
- [ ] 2.3 Daemon hardening: `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, mlock VK. Verify: `cat /proc/<daemon>/mem` from the same user fails, as tested in CI.

## 3. Sessions

- [ ] 3.1 Lease model, `smith session start`, the descendant check on every request (design D3). Verify: e2e for descendant allowed / outsider denied.
- [ ] 3.2 `smith status`, `revoke`, `lock`, expiry. Verify: e2e for TTL expiry and revoke exit 4.
- [ ] 3.3 Route `smith run` through the daemon when available. Verify: e2e shows no prompt inside a session.

## 4. Audit ledger

- [ ] 4.1 Ledger table, canonical encoding, hash chain, HMAC ratchet with key persistence in the same transaction (design D4). Verify: unit tests for append and verify, and tamper/delete/reorder detection.
- [ ] 4.2 Write `K_1` at vault init (M1 migration), and add `smith audit ls|verify [--full]`. Verify: the full-verify e2e with the recovery phrase.

## 5. Diagnostics and adversarial

- [ ] 5.1 Doctor checks `daemon.running`, `daemon.socket_perms`, `daemon.attestation_selftest`, `platform.ptrace_scope`, `platform.core_dumps`, `audit.chain`. Verify: snapshots.
- [ ] 5.2 Adversarial A4a (rogue same-UID client: Python, Node, `socat`, a copied `smith`). Verify: `run.sh A4a` shows all rejected and BLOCKED events present.

## 6. Milestone acceptance

- [ ] 6.1 Dogfood a full day with `smith session start -- claude`, then revoke mid-task. Verify: a later operation fails with exit 4 and `smith audit verify --full` passes.
