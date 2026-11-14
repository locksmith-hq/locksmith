# Spec Delta

## Purpose

Lets users hand support everything needed to diagnose a problem in one file that provably contains no secrets.

## ADDED Requirements

### Requirement: Secret-free bundle
`smith diag bundle` SHALL produce an archive of allowlisted diagnostic data that contains no secret values, license keys, tokens or vault contents. If any remain after redaction, it SHALL abort without writing.

#### Scenario: Canary everywhere
- **WHEN** canaries are planted in logs, config and environment and a bundle is created
- **THEN** the archive contains no encoding of any canary

### Requirement: Preview before sharing
The bundle command SHALL show a manifest of included files and sizes, and nothing SHALL be uploaded except by an explicit `smith diag upload` command.

#### Scenario: No implicit upload
- **WHEN** the user runs `smith diag bundle`
- **THEN** a local file is written and no network request is made
