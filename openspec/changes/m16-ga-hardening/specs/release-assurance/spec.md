# Spec Delta

## Purpose

Lets users and enterprises verify that the Locksmith artifacts they run were built from this repository by the official pipeline.

## ADDED Requirements

### Requirement: Build provenance
Every released artifact SHALL have signed build provenance and a software bill of materials published alongside it.

#### Scenario: Verify provenance
- **WHEN** a user runs `gh attestation verify` on a downloaded artifact
- **THEN** verification succeeds and names the release workflow

### Requirement: Self verification
`smith self verify` SHALL check the installed binaries against release metadata and provenance and report any mismatch.

#### Scenario: Modified binary
- **WHEN** an installed binary has been modified
- **THEN** `smith self verify` exits 1 and names the file
