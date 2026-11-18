# Tasks: X1 apps on all platforms

## 1. Spike and IPC trait [opus]
- [x] 1.1 Spike: compare `interprocess` and tokio named pipes for a round trip plus peer SID check; record versions, licences, last-release dates and the choice in design.md and progress.md.
- [x] 1.2 Introduce a transport trait in `ls-ipc` with the existing Unix implementation behind it; the public API is unchanged.
- [x] 1.3 Add the `cfg(windows)` named-pipe implementation with a current-user-only DACL and the SID peer check.
- [x] 1.4 Verify: `cargo nextest run -p ls-ipc` passes on Linux, including round trip and foreign-peer tests via the trait.

## 2. Windows builds for secret-touching crates [opus]
- [x] 2.1 Make `ls-vault` (SQLCipher with vendored OpenSSL), `ls-broker`, `smith-cli` and `locksmithd` compile under `cfg(windows)`, using the transport trait; no change to crypto or on-disk formats.
- [ ] 2.2 Replace Unix-only paths and permission calls (0600 file modes, socket paths) with a platform module that has an ACL equivalent on Windows.
- [ ] 2.3 Verify: `cargo nextest run --workspace` stays green on Linux and `cargo check --workspace --target x86_64-pc-windows-gnu` compiles where the toolchain allows.

## 3. Desktop on all platforms [sonnet]
- [ ] 3.1 Add the Windows branch of `secure_input.rs` and tray handling in `apps/desktop/src-tauri`; confirm the Tauri config bundles on Windows.
- [ ] 3.2 Add a daemon health IPC call and `scripts/desktop-smoke.sh` (launch headless, wait for health, exit 0, non-zero when the daemon is down).
- [ ] 3.3 Extend `just apps-build` to build web plus desktop on the host OS; add a test that it fails on a planted error.
- [ ] 3.4 Verify: `just apps-build` and `bash scripts/desktop-smoke.sh` on Linux.

## 4. Platform CI [sonnet]
- [ ] 4.1 Prepare the `ci-platforms.yml` change (drop the Windows exclusions, add `cargo test --workspace` to the Windows job, add Linux and Windows Tauri bundle jobs) as a patch in the PR description and open a `needs-owner` issue, because workflows are protected.
- [ ] 4.2 After the owner lands it, run `ci-platforms` once on the final commit, including `cargo test --workspace` and `scripts/desktop-smoke.sh` on macOS and Windows, and record the three results in progress.md.

## 5. Local verification [sonnet]
- [ ] 5.1 Run `just up`, the smoke test, `just apps-build`, then `just ci`.
