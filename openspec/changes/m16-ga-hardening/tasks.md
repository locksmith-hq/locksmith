# Tasks

## 1. Windows

- [ ] 1.1 Named-pipe IPC and attestation (design D1). Verify: Windows CI e2e with signed and unsigned clients.
- [ ] 1.2 TPM/Hello wrap. Verify: a manual test on 2 devices and a unit test with a CNG mock.
- [ ] 1.3 Job Object containment and daemon service install. Verify: Windows CI revoke-kill e2e.
- [ ] 1.0 Build SQLCipher on Windows (OpenSSL via vcpkg, static) and re-include `ls-vault` and `smith-cli` in the CI `windows-check`. Verify: `windows-2022` job runs `cargo check --workspace` with no excludes.
- [ ] 1.4 Port the redactor PTY (ConPTY), hooks paths and the relays. Verify: the full adversarial suite on `windows-2022`.

## 2. Linux TPM2

- [ ] 2.1 Optional TPM2-sealed wrap with PIN. Verify: swtpm-based CI test.

## 3. Distribution and supply chain

- [ ] 3.0 Clean-machine install + self-update test on a fresh macOS VM and an Ubuntu container (deferred from M0 7.1). Verify: recorded transcript in the PR.
- [ ] 3.1 MSI plus WinGet, an apt/rpm repo, cask and formula updates, devcontainer feature, GitHub Action. Verify: clean-VM installs per channel.
- [ ] 3.2 SLSA provenance, CycloneDX SBOM, `cargo-vet`, `smith self verify`. Verify: `gh attestation verify` in a release smoke job.

## 4. Assurance

- [ ] 4.1 External pentest (design D2) and fixes. Verify: the vendor retest letter shows criticals/highs at 0.
- [ ] 4.2 Full adversarial suite A0–A9 on macOS, Linux and Windows, live runs for Claude Code, Cursor and Codex. Verify: the nightly dashboard is green for 7 consecutive days.
- [ ] 4.3 Security docs: threat model, whitepaper, IR runbook, bug bounty policy. Verify: reviewed by an external advisor.
