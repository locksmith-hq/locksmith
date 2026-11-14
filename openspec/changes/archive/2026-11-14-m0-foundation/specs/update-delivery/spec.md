# Spec Delta

## Purpose

Delivers new Locksmith builds to installed machines safely, so testers and users always run a verified, current binary.

## ADDED Requirements

### Requirement: Verified self-update
`smith self update` SHALL replace the installed binaries only after verifying the release manifest signature against the embedded public key and the SHA-256 of the downloaded artifact.

#### Scenario: Valid update
- **WHEN** a newer signed release exists and the user runs `smith self update`
- **THEN** the binary is replaced and `smith --version` reports the new version

#### Scenario: Tampered artifact
- **WHEN** the downloaded artifact hash does not match the signed manifest
- **THEN** no file is replaced, the exit code is 1, and the error names the hash mismatch

### Requirement: Atomic replacement
A self-update SHALL either fully install the new binary or leave the previous binary untouched. It SHALL never leave a partially written executable.

#### Scenario: Interrupted download
- **WHEN** the network drops mid-download
- **THEN** the installed binary is unchanged and still runs

### Requirement: Update check
`smith self update --check` SHALL report the installed version, the latest available version and whether an update is available, without installing anything.

#### Scenario: Up to date
- **WHEN** the installed version equals the latest release
- **THEN** the command reports no update available and exits 0
