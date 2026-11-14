# Proposal: M16 GA Hardening

## Why

Before general availability and paid launch: Windows developers are a large share of agent users, a
security product needs an independent assessment, and installers must be trustworthy on every
platform.

## What Changes

- **Windows parity:** named-pipe IPC with client process and Authenticode attestation, a TPM 2.0 /
  Windows Hello wrap (CNG `MS_PLATFORM_CRYPTO_PROVIDER` with `NCRYPT_UI_POLICY`), Job Objects with
  kill-on-close for containment, a Windows service or per-user scheduled task for the daemon, a
  DPAPI-free design (VK only through Hello or passphrase).
- **Linux TPM2 (optional):** a VK wrap sealed to the TPM via `tss-esapi` with a PIN.
- **Installers:** Authenticode-signed MSI, WinGet manifest, a signed apt/rpm repository, an
  updated Homebrew cask and formula, the devcontainer feature, and a GitHub Action.
- **Supply chain:** reproducible builds where feasible, SLSA level 3 provenance via GitHub OIDC,
  SBOM (CycloneDX) per release, `cargo-vet` audits for crypto-adjacent dependencies.
- **External pentest** of the daemon, relays, update chain and license server, plus a public bug
  bounty at launch.
- **Full adversarial suite** (A0–A9) on all three OSes, live-agent runs for Claude Code, Cursor and
  Codex.
- **Docs:** a threat model page, security whitepaper, and incident response runbook
  (`docs/security/`).

## Usable outcome

Locksmith 1.0 is installable from official channels on macOS, Windows and Linux, with signed
provenance and an independent security report.

## Capabilities

### New Capabilities
- `platform-windows`: Windows-specific attestation, unlock, containment and service behaviour.
- `release-assurance`: Provenance, SBOM and verification of distributed artifacts.

### Modified Capabilities

## Out of scope

- Mobile companion approvals (backlog).

## Impact

`ls-platform::windows` (the `windows` crate), installer pipelines, `docs/security/`.
