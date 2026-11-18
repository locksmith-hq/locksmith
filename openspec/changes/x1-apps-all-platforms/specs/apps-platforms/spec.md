## ADDED Requirements

### Requirement: Cross-platform local IPC
`ls-ipc` SHALL offer the same client and server API over Unix sockets (macOS, Linux) and named pipes (Windows), and SHALL reject a peer whose OS user differs from the server's.

#### Scenario: Round trip on every OS
- **WHEN** a server is started and a client sends a request on the host OS transport
- **THEN** the client receives the response and the test passes on Linux locally and on all three OSes in `ci-platforms`

#### Scenario: Foreign peer refused
- **WHEN** a client with a different OS user connects
- **THEN** the server closes the connection without handling a request

### Requirement: Secret-touching crates build on Windows
`ls-vault`, `smith-cli`, `ls-broker` and `locksmithd` SHALL compile and pass their unit tests on Windows, with no exclusions in the Windows CI check.

#### Scenario: Windows check has no exclusions
- **WHEN** `ci-platforms` runs the Windows job
- **THEN** it checks and tests the whole workspace and the job passes

### Requirement: Desktop app launches on all platforms
The desktop app SHALL build, launch headless and answer a health call from the local daemon on macOS, Linux and Windows.

#### Scenario: Smoke launch
- **WHEN** `scripts/desktop-smoke.sh` runs against the built binary
- **THEN** it exits 0 after the app reports healthy, and non-zero if the daemon is unreachable

### Requirement: Apps build gate
`just apps-build` SHALL build the web console and the desktop app on the host OS and fail on any error.

#### Scenario: Gate fails on a broken app
- **WHEN** a type error is introduced in `apps/web`
- **THEN** `just apps-build` exits non-zero
