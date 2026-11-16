# Spec Delta

## Purpose

Lets related secrets be used together as a named group.

## ADDED Requirements

### Requirement: Run with a group
`smith run --group <name>` SHALL inject exactly the keys the binding pinned at session start lists for that group, and no others.

#### Scenario: Langfuse group
- **WHEN** the binding has `[groups.langfuse] keys = ["LANGFUSE_PUBLIC_KEY","LANGFUSE_SECRET_KEY"]` and the agent runs `smith run --group langfuse -- cmd`
- **THEN** the child sees those two variables and no other vault key

#### Scenario: Group added after session start
- **WHEN** the agent adds a group to `.locksmith.toml` after the session started and runs it
- **THEN** the run fails with an unknown-group error

### Requirement: Groups carry names only
Groups SHALL list key names only, and no group request or response SHALL carry a secret value.

#### Scenario: No value in group data
- **WHEN** `smith group ls` or `locksmith_list_keys` returns group information
- **THEN** the output contains key names only and the oracle finds no secret encodings
