# Spec Delta

## ADDED Requirements

### Requirement: Self-repair
`smith doctor --fix` SHALL apply the fix of each failing fixable check after showing what it will change and receiving confirmation, then re-run that check.

#### Scenario: Permissions repaired
- **WHEN** the config directory is 0755 and the user runs `smith doctor --fix` and confirms
- **THEN** the directory becomes 0700 and the check reports ok

### Requirement: Agent-readable output
`smith doctor --agent` SHALL output a concise list of failing checks with copyable remediation commands and SHALL omit vault paths and project secrets metadata beyond key counts.

#### Scenario: Agent mode
- **WHEN** an agent runs `smith doctor --agent`
- **THEN** the output lists failures and commands and contains no key names

### Requirement: Redacted structured logs
Locksmith SHALL write structured logs with rotation and retention, and SHALL never write secret values to logs at any level.

#### Scenario: Trace level canary
- **WHEN** trace logging is enabled during operations on canary secrets
- **THEN** no encoding of any canary appears in log files
