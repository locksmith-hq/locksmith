# Spec Delta

## Purpose

Gives users commands to organise secrets into projects and environments and to add, update, list, remove and export them without leaking values.

## ADDED Requirements

### Requirement: Projects and environments
Users SHALL be able to create, list and remove projects and, within a project, environments. A new project SHALL get a `development` environment by default.

#### Scenario: Default environment
- **WHEN** the user runs `smith project add api`
- **THEN** project `api` exists with environment `development`

### Requirement: Values never on the command line
`smith add` SHALL accept a secret value only from a no-echo interactive prompt, standard input, or a file, and SHALL reject a value passed as an argument.

#### Scenario: Value from stdin
- **WHEN** the user runs `printf %s "$V" | smith add STRIPE_KEY --stdin`
- **THEN** the secret is stored and nothing echoes the value

#### Scenario: Value as argument
- **WHEN** the user runs `smith add STRIPE_KEY sk_live_x`
- **THEN** the exit code is 2 and the error explains the supported input methods

### Requirement: Metadata-only listing
`smith ls` SHALL show key names, environments, versions and timestamps and SHALL never show values.

#### Scenario: Listing
- **WHEN** the user runs `smith ls --json`
- **THEN** the output contains names and metadata and no value field

### Requirement: Version history
Updating a secret SHALL create a new version and keep previous versions, and `smith history <key>` SHALL list versions without values.

#### Scenario: Update keeps history
- **WHEN** a secret is set twice
- **THEN** `smith history` lists two versions with the latest marked current

### Requirement: Human-only reveal
`smith reveal` SHALL require an interactive terminal, fresh passphrase entry, and the absence of a detected AI agent. By default it SHALL copy the value to the clipboard and clear it after 30 seconds.

#### Scenario: Non-interactive reveal
- **WHEN** `smith reveal KEY` runs with stdout not attached to a terminal
- **THEN** the exit code is 3 and no value is output

#### Scenario: Agent detected
- **WHEN** `smith reveal KEY` runs inside a Claude Code shell
- **THEN** the exit code is 3 and the message tells the user to run it in their own terminal

### Requirement: Export always available
`smith export` SHALL write all secrets of a project or environment to a 0600 file in env or JSON format after fresh passphrase entry, regardless of license state.

#### Scenario: Expired license export
- **WHEN** the license is expired and the user runs `smith export --format env --out backup.env`
- **THEN** the file is written with mode 0600 and contains all requested secrets
