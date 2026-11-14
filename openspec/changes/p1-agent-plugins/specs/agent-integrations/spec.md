# Spec Delta

## Purpose

Connects Locksmith to each supported agent framework, IDE and CI system with consistent behaviour and safe upgrades.

## ADDED Requirements

### Requirement: Detect and install
`smith integrations install` SHALL detect supported agents and IDEs present on the machine or in the project and install or update their integrations, showing changes before applying them.

#### Scenario: Claude Code and Cursor present
- **WHEN** both are installed and the user runs `smith integrations install`
- **THEN** both integrations are installed and `smith integrations ls` shows them as current

### Requirement: Behavioural parity
Every agent integration SHALL enforce the same guardrail decisions for equivalent actions, using the shared decision engine.

#### Scenario: cat .env across agents
- **WHEN** each supported agent attempts to read `.env`
- **THEN** each is blocked with the same reason and alternative

### Requirement: Compatibility checking
Locksmith SHALL detect integration, agent and smith version combinations outside the published compatibility matrix and report them in doctor with an update command.

#### Scenario: Old plugin
- **WHEN** the installed Claude Code plugin is older than the minimum for the installed smith
- **THEN** doctor warns and names `smith integrations update`

### Requirement: Container and CI support
The devcontainer feature SHALL let processes in a container use the host daemon through a forwarded socket, and the GitHub Action SHALL run steps with redaction and without writing secrets to the runner's disk.

#### Scenario: Devcontainer push
- **WHEN** an agent inside a devcontainer pushes to a private repo
- **THEN** the push succeeds through the host daemon and no credential exists in the container
