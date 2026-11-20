# Spec Delta

## Purpose

Defines how a Locksmith release is built, signed, described and verified so a user can check what they run without trusting the download location, and so no signing key ever lives in the repository.

## ADDED Requirements

### Requirement: Release assets are signed two ways
Every release SHALL include a minisign signature of the manifest (the trust root `smith` self-update embeds) and keyless cosign signatures for each archive, the manifest and each image, with the verifying bundle attached.

#### Scenario: Both signatures verify
- **WHEN** `scripts/verify-release.sh` runs on a downloaded release directory
- **THEN** the minisign check against the embedded public key and the cosign check against the release workflow identity both pass

#### Scenario: Tampered asset rejected
- **WHEN** one byte of an archive or the manifest is changed
- **THEN** `scripts/verify-release.sh` exits non-zero and names the asset

### Requirement: Checksums cover every asset
The manifest SHALL list the name and SHA-256 of every binary archive for macOS and Linux (arm64 and x86_64), and no asset SHALL be installable that the manifest omits.

#### Scenario: Manifest complete
- **WHEN** the manifest is generated for a release directory
- **THEN** it lists exactly the four platform archives and the generation fails if one is missing or has an unsafe name

### Requirement: SBOM and provenance
Every release SHALL include a CycloneDX SBOM for the binaries and each image, and a build provenance attestation binding each asset to the commit and workflow that built it.

#### Scenario: Provenance verifies
- **WHEN** `gh attestation verify` or `cosign verify-attestation` runs on a release asset
- **THEN** it passes and names the repository, the tag and the release workflow

### Requirement: No signing key in the repository
Signing keys SHALL be referenced by secret name only; the cosign flow SHALL use short-lived identity-bound certificates and no stored private key, and the secret scan SHALL find no private key material in the tree or release assets.

#### Scenario: Scan is clean
- **WHEN** the leak scan and gitleaks run over the repository and a dry-run release directory
- **THEN** neither reports a private key or token

### Requirement: Release dry run
The release workflow SHALL offer a dry-run mode that builds, signs with a throwaway test identity where real signing is unavailable, and verifies everything without creating a GitHub release or pushing images.

#### Scenario: Dry run publishes nothing
- **WHEN** the dry run executes on a branch
- **THEN** no release, tag or registry image is created and the verification step runs

### Requirement: Release source and version are consistent
The release tag SHALL equal the workspace version, prereleases (tags with a hyphen) SHALL be marked as such, and the repository slug used by the installer, self-update and the workflow SHALL be the public `locksmith-hq/locksmith`.

#### Scenario: Tag mismatch
- **WHEN** a tag differs from the workspace version
- **THEN** the release job fails before signing anything
