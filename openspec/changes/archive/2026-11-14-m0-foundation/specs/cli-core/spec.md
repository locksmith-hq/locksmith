# Spec Delta

## Purpose

Defines the conventions every `smith` command follows so humans, scripts and agents can rely on its output and exit codes.

## ADDED Requirements

### Requirement: Version reporting
`smith --version` SHALL print the semantic version, git commit, build target and release channel. With `--json` it SHALL print them as one JSON object.

#### Scenario: Human version
- **WHEN** the user runs `smith --version`
- **THEN** stdout contains `smith <semver> (<commit> <target> <channel>)` and the exit code is 0

#### Scenario: JSON version
- **WHEN** the user runs `smith --version --json`
- **THEN** stdout is a single JSON object with keys `version`, `commit`, `target`, `channel`

### Requirement: Machine-readable output
Every command SHALL accept `--json`. In JSON mode stdout SHALL contain exactly one JSON document, and all human-oriented text SHALL go to stderr.

#### Scenario: JSON purity
- **WHEN** any command runs with `--json`
- **THEN** stdout parses as exactly one JSON value

### Requirement: Stable exit codes
The CLI SHALL use exit code 0 for success, 1 for generic failure, 2 for usage errors, 3 when blocked by Locksmith policy, 4 when the vault is locked or authentication is required, and 5 when a referenced item does not exist.

#### Scenario: Usage error
- **WHEN** the user passes an unknown flag
- **THEN** the exit code is 2 and stderr shows usage help

### Requirement: Shell completions
`smith completions <bash|zsh|fish|powershell>` SHALL print a completion script for the named shell.

#### Scenario: Zsh completions
- **WHEN** the user runs `smith completions zsh`
- **THEN** stdout contains a valid zsh completion script and the exit code is 0
