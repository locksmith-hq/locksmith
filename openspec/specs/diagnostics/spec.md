# diagnostics Specification

## Purpose
Gives users, support and agents one command that explains whether Locksmith is healthy on this machine and how to fix it when it is not.

## Requirements

### Requirement: Doctor runs all registered checks
`smith doctor` SHALL run every registered check and report, for each, a stable dotted id, a status of ok, warn, fail or skip, a one-line summary, and a remediation hint when the status is warn or fail.

#### Scenario: Healthy machine
- **WHEN** all checks pass
- **THEN** every check reports ok or skip and the exit code is 0

#### Scenario: Failing check
- **WHEN** at least one check reports fail
- **THEN** the exit code is 1 and the failing check shows a remediation hint

### Requirement: Doctor JSON contract
`smith doctor --json` SHALL emit an object with `schema` set to `doctor.v1`, the Locksmith version, the platform, and an array of check results. The schema version SHALL change on any breaking change to this shape.

#### Scenario: JSON doctor
- **WHEN** the user runs `smith doctor --json`
- **THEN** stdout is a `doctor.v1` object that validates against the published JSON schema

### Requirement: Doctor never reveals secrets
Doctor output SHALL NOT contain secret values, key material, license keys or tokens, in any status or mode.

#### Scenario: Canary absent
- **WHEN** the adversarial oracle plants canary secrets and runs `smith doctor --json`
- **THEN** no encoding of any canary appears in the output

### Requirement: Foundation checks
M0 SHALL register checks for supported OS and architecture, config and data directory ownership with mode 0700, binary signature validity, and reachability of the update endpoint.

#### Scenario: Insecure config directory
- **WHEN** the config directory is group- or world-readable
- **THEN** check `fs.config_dir_perms` reports fail with a remediation naming the `chmod 700` fix
