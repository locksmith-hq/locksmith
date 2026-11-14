# Tasks

## 1. Daemon and protocol

- [x] 1.1 `ls-ipc`: framed CBOR protocol with versioning, request/response enums, and a schema test asserting no secret-value field in any response. Verify: `cargo test -p ls-ipc`. Done: `cargo test -p ls-ipc` (`no_response_carries_secret_material` walks every response variant: no byte strings, no value-like field names).
- [x] 1.2 `locksmithd`: socket in the 0700 runtime dir, single-instance lock, unlock/lock state, fail-closed restart, `smith daemon install|uninstall|status`. Verify: e2e for the second-instance message and lock-after-restart. Done: `crates/smith-cli/tests/session.rs` (`second_instance_exits_with_message`, `restart_fails_closed`).
- [ ] 1.3 Auto-lock on idle, screen lock and sleep (design D5). Verify: an integration test fakes the D-Bus signal on Linux, and a manual macOS checklist covers the rest. Partial: idle lock e2e (`idle_timeout_locks_the_vault`) and Linux logind `Lock`/`PrepareForSleep` signals faked on a private D-Bus (`ls-platform` `fake_logind_signals_trigger_lock`, zbus 6.3) pass. macOS screen-lock polling and sleep detection by clock skew have not been exercised (manual checklist pending), so this stays open.

## 2. Attestation (`ls-platform`)

- [x] 2.1 macOS audit token plus code requirement check. Verify: a test binary signed with an ad-hoc identity is classified unknown, and the release-signed `smith` is accepted (CI with a test signing cert). As built: cdhash pinning instead of a Team ID requirement (no release signing identity yet, see design "As built"). Verified by `ls-broker` `manifest_classifies_only_pinned_same_uid_binaries` (pinned binary accepted, other code unknown) and A4a (ad hoc re-signed modified `smith` copy rejected). Team ID pinning is not tested in CI.
- [x] 2.2 Linux peercred, pidfd, starttime and exe-hash manifest. Verify: a test where a copy of `smith` with one flipped byte is rejected. Done: `ls-broker` manifest test flips one byte (Linux) and A4a rejects a byte-modified `smith` copy on Linux; run in Docker on Linux arm64.
- [x] 2.3 Daemon hardening: `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, mlock VK. Verify: `cat /proc/<daemon>/mem` from the same user fails, as tested in CI. Done: `same_user_cannot_read_daemon_memory` (Linux; a dumpable control child is readable). macOS uses PT_DENY_ATTACH.

## 3. Sessions

- [x] 3.1 Lease model, `smith session start`, the descendant check on every request (design D3). Verify: e2e for descendant allowed / outsider denied. Done: session.rs `descendant_allowed_without_prompt_and_value_never_printed`, `outsider_with_forged_session_is_denied`, `session_start_needs_passphrase_even_when_unlocked`.
- [x] 3.2 `smith status`, `revoke`, `lock`, expiry. Verify: e2e for TTL expiry and revoke exit 4. Done: session.rs `ttl_expiry_exits_4`, `revoke_blocks_next_run_and_is_audited`, `status_lists_two_sessions`.
- [x] 3.3 Route `smith run` through the daemon when available. Verify: e2e shows no prompt inside a session. Done: same descendant e2e (no prompt inside a session; the daemon spawns the child, pipes not a PTY).

## 4. Audit ledger

- [x] 4.1 Ledger table, canonical encoding, hash chain, HMAC ratchet with key persistence in the same transaction (design D4). Verify: unit tests for append and verify, and tamper/delete/reorder detection. Done: `cargo test -p ls-vault audit` (append/verify, edit/delete/reorder/truncate detection, forward security against a holder of the current key).
- [x] 4.2 Write `K_1` at vault init (M1 migration), and add `smith audit ls|verify [--full]`. Verify: the full-verify e2e with the recovery phrase. Done: K_1 written at `Vault::create`; pre-M3 vaults get an unanchored root (`pre_m3_vault_gets_an_unanchored_ledger_and_says_so`); session.rs `lock_then_run_needs_new_session_and_audit_full_verify_passes`.

## 5. Diagnostics and adversarial

- [x] 5.1 Doctor checks `daemon.running`, `daemon.socket_perms`, `daemon.attestation_selftest`, `platform.ptrace_scope`, `platform.core_dumps`, `audit.chain`. Verify: snapshots. Done: exact-output unit tests in `crates/ls-broker/src/doctor.rs`; checks appear in `smith doctor`.
- [x] 5.2 Adversarial A4a (rogue same-UID client: Python, Node, `socat`, a copied `smith`). Verify: `run.sh A4a` shows all rejected and BLOCKED events present. Done: `tests/adversarial/run.sh A4a` passes on macOS (python, node, modified smith) and Linux (python, modified smith); socat skipped where not installed.

## 6. Milestone acceptance

- [x] 6.1 Dogfood a full day with `smith session start -- claude`, then revoke mid-task. Verify: a later operation fails with exit 4 and `smith audit verify --full` passes. Simulated, as the user asked: throwaway LOCKSMITH_HOME, fake project with a binding, a scripted agent running three `smith run` test commands, revoke mid-task; the next run exited 4, the ledger showed ACCESS/REVOKE/BLOCKED, and `smith audit verify --full` verified every MAC. A real day with `claude` has not been run.
