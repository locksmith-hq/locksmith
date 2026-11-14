# Spec Delta

## Purpose

Keeps secrets and secret-adjacent local files out of git history through project setup, staging checks and commit-time scanning.

## ADDED Requirements

### Requirement: One-command project setup
`smith init` SHALL configure the project binding, gitignore entries, pre-commit scanner and agent hooks for every detected agent, SHALL show the planned changes before applying them, and SHALL be idempotent.

#### Scenario: Re-run
- **WHEN** `smith init --yes` runs twice
- **THEN** the second run makes no changes

#### Scenario: Existing hook manager
- **WHEN** the repo uses husky
- **THEN** the scanner is added to the husky pre-commit hook rather than replacing it

### Requirement: Commit-time scanning
The pre-commit scanner SHALL block commits whose staged content contains an active vault secret in any supported encoding, or a high-confidence generic secret pattern.

#### Scenario: Staged secret
- **WHEN** a staged file contains the value of `DATABASE_URL`
- **THEN** the commit fails and the output names the file, line and key

### Requirement: Sensitive files not staged by agents
Agent requests to stage local agent settings or secret-bearing files SHALL be denied.

#### Scenario: Stage local settings
- **WHEN** an agent requests `git add .claude/settings.local.json`
- **THEN** the request is denied with a reason

### Requirement: Standalone scan
`smith scan [--staged | PATH]` SHALL report findings with file, line and key name, never values, and SHALL exit 1 when anything is found.

#### Scenario: Clean tree
- **WHEN** no findings exist
- **THEN** `smith scan` exits 0
