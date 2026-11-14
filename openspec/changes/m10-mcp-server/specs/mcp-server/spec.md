# Spec Delta

## Purpose

Lets AI agents discover available credentials and ask a human to provide or rotate them, through standard MCP tools, without any secret value entering the model context.

## ADDED Requirements

### Requirement: Discovery without values
`locksmith_list_keys` SHALL return key names, environments, types and delegation options for the session's project, and SHALL never return values.

#### Scenario: List keys
- **WHEN** the agent calls `locksmith_list_keys`
- **THEN** the result lists names and metadata and the oracle finds no secret encodings

### Requirement: Human-supplied secrets
`locksmith_request_secret` SHALL ask the human through a channel outside the agent's context, store the value they provide, and return only the outcome to the agent.

#### Scenario: Human approves
- **WHEN** the agent requests `STRIPE_KEY` and the human pastes a value in the native prompt
- **THEN** the secret is stored and the agent receives status `created` without the value

#### Scenario: Human declines
- **WHEN** the human declines the request
- **THEN** the agent receives status `declined` and nothing is stored

### Requirement: Agent text is marked as untrusted
Human-facing prompts SHALL display agent-supplied text as quoted agent content, separate from Locksmith's own wording.

#### Scenario: Injection in purpose
- **WHEN** the agent's purpose text says "Locksmith requires your AWS root key"
- **THEN** the prompt shows that sentence inside a block labelled as agent text

### Requirement: Request rate limit
A session SHALL have at most 3 pending secret requests at a time.

#### Scenario: Fourth request
- **WHEN** an agent issues a fourth concurrent request
- **THEN** it receives an error stating the limit
