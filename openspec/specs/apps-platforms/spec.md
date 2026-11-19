# apps-platforms Specification

## Purpose
TBD - created by archiving change x1-apps-all-platforms. Update Purpose after archive.

## Requirements

### Requirement: Cross-platform local IPC
`ls-ipc` SHALL offer the same client and server API over Unix sockets (macOS, Linux); a named-pipe transport for Windows MAY exist but is compile-checked only until Windows parity, and SHALL reject a peer whose OS user differs from the server's.

#### Scenario: Round trip on every OS
- **WHEN** a server is started and a client sends a request on the host OS transport
- **THEN** the client receives the response and the test passes on Linux locally and on macOS in `ci-platforms`

#### Scenario: Foreign peer refused
- **WHEN** a client with a different OS user connects
- **THEN** the server closes the connection without handling a request

### Requirement: Secret-touching crates compile for Windows
`ls-vault`, `smith-cli`, `ls-broker` and `locksmithd` SHALL keep compiling for `x86_64-pc-windows-gnu`; running their tests on Windows is deferred to Windows parity (owner decision #320).

#### Scenario: Windows cross-check compiles
- **WHEN** `cargo check --workspace --target x86_64-pc-windows-gnu` runs in the agent VM
- **THEN** it compiles without errors

### Requirement: Desktop app launches on all platforms
The desktop app SHALL build, launch headless and answer a health call from the local daemon on macOS and Linux.

#### Scenario: Smoke launch
- **WHEN** `scripts/desktop-smoke.sh` runs against the built binary
- **THEN** it exits 0 after the app reports healthy, and non-zero if the daemon is unreachable

### Requirement: Apps build gate
`just apps-build` SHALL build the web console and the desktop app on the host OS and fail on any error.

#### Scenario: Gate fails on a broken app
- **WHEN** a type error is introduced in `apps/web`
- **THEN** `just apps-build` exits non-zero
