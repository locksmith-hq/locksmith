# Spec Delta

## Purpose

Defines how the `smith` CLI is installed on macOS and Linux and how the installer proves what it installed.

## ADDED Requirements

### Requirement: Verifying install script
`scripts/install.sh` SHALL detect macOS or Linux and arm64 or x86_64, download the matching archive and signed manifest from the public release without requiring `gh` or any login, verify the minisign signature and SHA-256 before installing, and refuse to install on any mismatch.

#### Scenario: Good install
- **WHEN** the script runs against a local test release directory with a valid signature
- **THEN** `smith` is installed to the chosen directory and `smith --version` matches the release

#### Scenario: Bad signature or hash
- **WHEN** the manifest signature or an archive hash does not verify
- **THEN** nothing is installed and the script exits non-zero with the failing check named

#### Scenario: Missing verifier
- **WHEN** `minisign` is not installed
- **THEN** the script verifies with a bundled pinned verifier or stops and says how to install one; it never silently skips verification

#### Scenario: Unsupported platform
- **WHEN** the script runs on Windows or an unknown architecture
- **THEN** it exits with a clear unsupported-platform message

### Requirement: Homebrew formula
The release SHALL produce a Homebrew formula for `smith` generated from the signed manifest (URLs and SHA-256 only), installable from a tap on macOS and Linux.

#### Scenario: Formula matches manifest
- **WHEN** the formula is generated for a release directory
- **THEN** every URL and checksum in it equals the manifest entry for that platform

### Requirement: Installer is not a path to a secret
The installer SHALL write only the `smith` binary (and an optional shell completion), SHALL NOT ask for, read or store any credential, and SHALL print no environment values.

#### Scenario: No credential access
- **WHEN** the installer runs under a trace of file and environment reads in the test
- **THEN** it reads no credential file and prints no environment variable value

### Requirement: Self-update stays verified
`smith` self-update SHALL fetch from the public release source and keep verifying the minisign manifest signature and SHA-256 before replacing the binary.

#### Scenario: Update with a bad signature
- **WHEN** self-update is given a manifest with an invalid signature
- **THEN** the binary is unchanged and the error says the signature failed
