# Tasks

## 1. Capabilities

- [ ] 1.1 Exec-chain classifier (design D1) with an argv pattern table and tests over 50 real process trees captured from npm, pip, cargo and make. Verify: classifier unit tests.
- [ ] 1.2 Capability issue, verify and expire, plus FD passing via socketpair and the env fallback (design D2). Verify: tests for reuse-for-another-target rejected and 61 s expiry.
- [ ] 1.3 Policy schema `[capabilities]` in `.locksmith.toml` with defaults. Verify: a parse and validation test.

## 2. Containment backends

- [ ] 2.1 Linux: the systemd-run user scope backend plus the subreaper fallback. Verify: e2e double-fork tracking, both backends in CI (systemd container and plain container).
- [ ] 2.2 macOS: process group plus kqueue tracking, and the optional Seatbelt profile (design D4). Verify: e2e double-fork on macOS CI, and the Seatbelt denies `cat ~/.aws/credentials`.
- [ ] 2.3 `smith revoke --kill` ordering and escaped-process reporting (design D3). Verify: the e2e kill test lists survivors (simulated by an ignoring-SIGTERM, SIGKILL-proof stub via a `ptrace`-stopped process).

## 3. Diagnostics and adversarial

- [ ] 3.1 Doctor checks `containment.backend`, `containment.seatbelt`. Verify: snapshots.
- [ ] 3.2 **Gate A4**: a hostile postinstall fixture package tries the socket, env scrape, capability theft and relays. Verify: `run.sh A4` passes.
- [ ] 3.3 **Gate A5**: revoke under load with concurrent Git, HTTP and AWS loops. Verify: `run.sh A5` shows no success after the revoke timestamp, and no processes after 5 s.
