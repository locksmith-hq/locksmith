# secret-execution Specification

## Purpose
Lets users run any command with the secrets it needs, without writing them to disk or putting them in shell history.

## Requirements

### Requirement: Run with injected secrets
`smith run -- <cmd>` SHALL start the command with the selected secrets added to its environment and SHALL exit with the command's exit code.

#### Scenario: Exit code passthrough
- **WHEN** the user runs `smith run -- sh -c 'exit 7'`
- **THEN** smith exits with code 7

### Requirement: Project binding
A committed `.locksmith.toml` SHALL name the project, default environment and allowed keys, and SHALL never contain secret values. `smith run` SHALL inject only keys listed in the binding or in `--only`.

#### Scenario: Only bound keys injected
- **WHEN** the binding lists `DATABASE_URL` and the environment also holds `STRIPE_KEY`
- **THEN** the child sees `DATABASE_URL` and not `STRIPE_KEY`

#### Scenario: Secret in binding rejected
- **WHEN** `.locksmith.toml` contains a value that matches a stored secret
- **THEN** `smith run` refuses with exit code 3 and names the offending line

### Requirement: Locksmith variables not inherited
The child environment SHALL NOT contain any `LOCKSMITH_` prefixed variable from the parent.

#### Scenario: Session variable stripped
- **WHEN** the parent has `LOCKSMITH_SESSION` set
- **THEN** the child environment does not contain it

### Requirement: Honest assurance label
`smith run --explain` SHALL state that environment injection lets the child and same-user processes read the injected values, and SHALL name the delegated alternatives.

#### Scenario: Explain
- **WHEN** the user runs `smith run --explain`
- **THEN** the output names the residual risks and the git, http, db and aws delegation commands

### Requirement: Names-only template
`smith env-template` SHALL write an example env file containing key names and empty values only.

#### Scenario: Template contents
- **WHEN** the user runs `smith env-template > .env.example`
- **THEN** every line has the form `KEY=` with no value

### Requirement: Agent injection warning
`smith run --explain` SHALL warn that injecting secrets into an AI agent process is unsafe, because the agent's tools return output to the model before redaction, and SHALL point to delegated access instead.

#### Scenario: Explain warns about agents
- **WHEN** the user runs `smith run --explain`
- **THEN** the output states that secrets should not be injected into AI agents and names delegated access as the alternative
