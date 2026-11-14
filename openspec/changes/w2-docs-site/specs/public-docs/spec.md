# Spec Delta

## Purpose

Provides accurate, versioned documentation for humans and AI agents, with reference sections generated from the code.

## ADDED Requirements

### Requirement: Generated references stay in sync
The CLI, configuration schema, doctor checks and MCP tool references SHALL be generated from the code at build time, and the docs build SHALL fail if generation fails.

#### Scenario: New flag
- **WHEN** a new CLI flag is added in code
- **THEN** the next docs build includes it without manual edits

### Requirement: Every block links to docs
Each block message and doctor remediation SHALL include a stable docs URL that resolves to an explanation and the supported alternative.

#### Scenario: Link check
- **WHEN** CI collects all docs URLs from rule and check definitions
- **THEN** every URL resolves to an existing anchor

### Requirement: Agent-readable docs
The site SHALL publish `llms.txt` and `llms-full.txt` summarising the supported workflows.

#### Scenario: llms.txt
- **WHEN** an agent fetches `/llms.txt`
- **THEN** it receives a plain-text index of guides with URLs
