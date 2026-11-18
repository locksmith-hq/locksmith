## Context
Observed: `crates/ls-ipc/src/lib.rs` uses `std::os::unix::net`; `apps/desktop/src-tauri` is outside the root workspace (webkit/gtk) with macOS (objc2) and Linux (gtk) secure-input code and no Windows branch; the Windows job in `ci-platforms.yml` is `cargo check` with five crates excluded; the macOS job runs `tauri build --debug --bundles app`.

## Decisions and evidence
| Decision | Alternatives rejected | Evidence |
|---|---|---|
| Named pipes via `tokio::net::windows::named_pipe` / `interprocess` crate behind one trait | Windows AF_UNIX sockets (Win10 1803+, no peer-credential API); TCP loopback (any local process can connect) | Task 1.1 spike picks between `interprocess` and tokio's pipes by running the same round-trip and peer-SID test; record result in progress.md |
| Peer check on Windows: compare the pipe client's SID with the server's token SID; pipe created with a DACL for the current user only | Trust the default pipe ACL | Microsoft named-pipe security docs (cite in spike) |
| Vendor OpenSSL for SQLCipher on Windows (`openssl-src`/`vendored`) | Require a system OpenSSL; drop SQLCipher on Windows | Removes the exclusion without an install step; confirm build time in the spike |
| Smoke test = headless launch plus an IPC health call, not UI automation | WebDriver/tauri-driver e2e on three OSes | Costs few CI minutes; UI tests stay in the console's Playwright suite (T3) |
| Platform CI stays manual (`ci-platforms`) | Per-PR matrix | AGENTS.md CI policy: macOS ~10x and Windows ~2x minutes |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| `interprocess` (candidate) | MIT/Apache-2.0 | spike to pin | spike to record | cross-platform local sockets and pipes | permissive, fine anywhere |
| `windows`/`windows-sys` | MIT/Apache-2.0 | spike to pin | spike to record | SID lookup for the peer check | permissive |
| `openssl-src` | MIT/Apache-2.0 | spike to pin | spike to record | vendored OpenSSL for SQLCipher | permissive |
| `tauri` 2 | MIT/Apache-2.0 | already used | existing | desktop shell | permissive |
Built in-house: only the thin transport trait and the peer-identity check; searched crates.io for a maintained peer-credential crate first (spike records the result).

## Risks
- Windows-only failures cannot be reproduced in the agent VM (Linux). Mitigation: keep platform code behind `cfg(windows)` modules with trait-level tests that run on Linux, and run `ci-platforms` once at the end of each group that touches Windows code (budget: manual runs only, see Actions minutes policy).
- Peer-identity weakening on a new OS is a security regression: the foreign-peer test must run on Windows too.

## How an agent debugs this
`just up` is not needed for IPC. Use `cargo nextest run -p ls-ipc`, `just apps-build`, `scripts/desktop-smoke.sh`; for Windows failures read the `ci-platforms` job logs via `gh api .../actions/jobs/<id>/logs`. Daemon logs and traces go to the usual Grafana/OTel stack from `just up`.
