# Spec Delta

## Purpose

Gives the team aggregate signals about reliability and usage only from users who opt in, under a published, inspectable schema.

## ADDED Requirements

### Requirement: Off by default
Telemetry and crash reporting SHALL be disabled until the user explicitly enables them, and SHALL be disableable at any time with one command.

#### Scenario: Fresh install
- **WHEN** Locksmith is freshly installed
- **THEN** no telemetry or crash data is sent

### Requirement: Inspectable payload
`smith telemetry preview` SHALL show the exact next payload, which SHALL contain only the published schema fields and no paths, project names, key names or hostnames.

#### Scenario: Preview
- **WHEN** the user runs `smith telemetry preview`
- **THEN** the output is a `telemetry.v1` JSON document matching the published schema

### Requirement: Local crash capture
A crash SHALL produce a local, redacted crash report, and the user SHALL be asked before it is included anywhere.

#### Scenario: Panic
- **WHEN** smith panics
- **THEN** a crash report is saved locally and the next run offers to include it in a support bundle
