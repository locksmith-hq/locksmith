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

## 2026-11-18 worker
- Task: 1.2, 1.4 - done
- Verified: `just ci` -> exit 0; `cargo nextest run -p ls-ipc` -> 14 passed (6 new in tests/transport.rs, foreign-peer test ran as root); independent Opus evaluator PASS
- Notes for next session: `Transport`/`Listener` traits in crates/ls-ipc/src/transport.rs, `Client<T = DefaultTransport>`; no new non-dev deps. The peer-uid check still lives in ls_platform + ls_broker, not ls-ipc: 1.3 should add peer identity to the trait and move the Unix check behind it, and the foreign-peer test should then exercise the shipped check (it skips silently when not root). locksmithd still binds UnixListener directly: switch to Listener::bind in 2.1. 1.1 stays unticked (compile-only spike). Next: 1.3 (Opus).

## 2026-11-18 worker
- Task: 1.1 - done (ticked)
- Verified: design.md and progress.md both record versions, licences, last-release dates and the choice; re-checked against the crates.io API today: tokio 1.54.1 MIT 2026-10-21, windows-sys 0.61.2 MIT OR Apache-2.0 2025-10-06, interprocess 2.4.8 0BSD OR Apache-2.0 2026-11-08 (recvmsg 1.0.0 and doctest-file 1.1.1 0BSD), openssl-src 400.0.2+4.0.3 MIT/Apache-2.0 2026-10-01 -> all match; Cargo.lock has tokio 1.54.1 and windows-sys 0.61.2. Choice: tokio named pipes plus windows-sys.
- Notes for next session: the spike's runtime round trip on Windows is still owed by task 4.2 (recorded in design.md risks).

## 2026-11-18 worker
- Task: 1.3 - done (ticked; compile-verified for Windows, runtime pending 4.2)
- Verified: `cargo check -p ls-ipc` and `cargo clippy -p ls-ipc --all-targets -- -D warnings` clean on Linux; `cargo clippy --target x86_64-pc-windows-gnu -p ls-ipc --all-targets -- -D warnings` clean; `cargo build --target x86_64-pc-windows-gnu -p ls-ipc --tests` links the Windows test .exe; `cargo nextest run -p ls-ipc` -> 17 passed (3 new pipe-name/SDDL unit tests); `cargo deny check bans licenses sources` ok; `cargo fmt --check`, tree-check ok. NOT verified: the pipe tests in tests/transport_windows.rs were not executed (no Windows host or wine); task 4.2 must run them. No independent evaluator run.
- What: crates/ls-ipc/src/transport/windows.rs: `PipeStream`/`PipeListener` (= `DefaultTransport`/`DefaultListener` on Windows) over tokio named pipes driven by a private 1-worker runtime, so the traits stay blocking. Every instance gets the protected SDDL DACL `D:P(A;;GA;;;<own SID>)`, `reject_remote_clients`, `first_pipe_instance` on bind; accept closes a peer whose token SID differs (via GetNamedPipeClientProcessId), connect refuses a server of another user (anti-squatting). `pipe_name(path)` maps the socket path to `\\.\pipe\locksmith-<path>`. Deps (cfg(windows) only, both already in Cargo.lock): tokio, windows-sys. `#![allow(unsafe_code)]` is scoped to that module, each unsafe block has a SAFETY note. lib.rs frame tests moved from UnixStream::pair to std::io::pipe so they compile and run on Windows.
- Notes for next session: peer identity uses the PID, so a PID-reuse race exists between connect and the SID lookup; the DACL is the primary control. Do not call the blocking pipe API from inside a tokio runtime thread (locksmithd 2.1). The foreign-user test on Windows needs a second account on the runner (4.2).

## 2026-11-18 harriet worker
- Task: 1.1, 1.3 - done (1.3 compile-checked for x86_64-pc-windows-gnu only; Windows run still needed in 4.2)
- Verified: just ci -> exit 0
- Notes for next session: next is 2.1/2.2 (opus). Pipe API must not be called inside a tokio runtime thread. Independent review of unsafe in transport/windows.rs left to merge-review.
