# Progress: x1-apps-all-platforms

## 2026-11-18 04:09 worker
- Task: planning (proposal, spec, design, tasks) - done
- Verified: openspec validate x1-apps-all-platforms -> valid
- Notes for next session: Windows crates cannot be tested in the Linux VM; workflow edits to ci-platforms.yml are protected (task 4.1 needs a needs-owner issue). Spike 1.1 picks the named-pipe crate.

## 2026-11-18 04:11 worker
- Task: planning review fix - done
- Verified: openspec validate x1-apps-all-platforms -> valid
- Notes for next session: review FAIL on 725b8cf (no Windows cargo test / smoke); tasks 4.1/4.2 widened; await re-review then merge.

## 2026-11-18 04:12 UTC worker
- Task: none - blocked
- Verified: merge-gate.sh 219 -> GATE FAIL 6 (review verdict FAIL on 725b8cf, before the fix commits 88de4b8 and 56740ce); gates 1-5 ok
- Notes for next session: the review FAIL predates the Windows test fix. Check that merge-review posts a verdict for 56740ce (or the current head) before re-running the gate. Do not push a no-op to re-trigger review.

## 2026-11-18 worker
- Task: 1.1 - blocked
- Verified: crates.io metadata only: interprocess 2.4.8 (0BSD OR Apache-2.0, updated 2026-11-08), tokio 1.54.1 (MIT, already in workspace); no Windows target or toolchain in the VM, so the round-trip and peer-SID spike could not run. Task not ticked.
- Notes for next session: ls-ipc (crates/ls-ipc/src/lib.rs) uses std::os::unix::net::UnixStream directly (Client.stream is public), so the transport trait (1.2) must change that field. Install the x86_64-pc-windows-gnu target and mingw if the network allows; otherwise 1.1 and 1.3 need a Windows runner (owner decision via ci-platforms). Opus tier needed for 1.x-2.x.

## 2026-11-18 worker
- Task: 1.1 - spike done, compile-verified only (not ticked)
- Verified: a throwaway crate outside the repo with both candidates (server and client round trip, current-user-only SDDL DACL, peer-SID check both ways through windows-sys) passes `cargo +1.100.0 check`, `clippy` (0 warnings) and `build` for x86_64-pc-windows-gnu; the .exe links. `cargo deny check` with deny.toml: tokio variant all ok, interprocess variant rejects 0BSD (recvmsg 1.0.0, doctest-file 1.1.1). Versions from crates.io: tokio 1.54.1 MIT 2026-10-21; windows-sys 0.61.2 MIT OR Apache-2.0 2025-10-06; interprocess 2.4.8 0BSD OR Apache-2.0 2026-11-08; openssl-src 400.0.2+4.0.3 2026-10-01. NOT verified: the round trip was not run (no Windows host or wine); task 4.2 must run it on a Windows runner.
- Choice: tokio named pipes plus windows-sys. Both are already in Cargo.lock and add no crates; interprocess adds 5 crates and needs 0BSD allowed. What interprocess offers (safe SDDL, `client_process_id`) costs one `unsafe` call and about 30 lines with windows-sys.
- Notes for next session: with tokio, build SECURITY_ATTRIBUTES per instance (raw pointers are !Send) and pass them to every new instance. deny.toml bans openssl-sys, which conflicts with the vendored-OpenSSL decision for SQLCipher; resolve that before 2.1.

## 2026-11-18 worker
- Task: 1.1 - blocked (spike recorded, not ticked)
- Verified: openspec validate x1-apps-all-platforms -> valid; no independent evaluator run, because the runtime round trip could not execute on Linux
- Notes for next session: x86_64-pc-windows-gnu target and gcc-mingw-w64 install fine in the VM (rustup target add; apt-get install gcc-mingw-w64-x86-64), so Windows code can be cross-checked. 1.2 (transport trait in ls-ipc, Unix impl only) needs no Windows host and can proceed next; tick 1.1 only after 4.2 runs the pipe round trip on a Windows runner or the owner accepts the compile-only spike. deny.toml bans openssl-sys, which clashes with vendored OpenSSL for SQLCipher on Windows (task 2.1): decide before 2.1.
