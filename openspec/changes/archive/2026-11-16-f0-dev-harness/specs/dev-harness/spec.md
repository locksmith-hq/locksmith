## ADDED Requirements

### Requirement: One-command local stack
The repository SHALL start every local dependency with `just up` and stop it with `just down`, binding only to 127.0.0.1.

#### Scenario: Stack comes up healthy
- **WHEN** a developer runs `just up` on a clean machine with Docker
- **THEN** postgres, lgtm, openbao and upstream report healthy within 120 seconds
- **AND** `just harness-check` exits 0

#### Scenario: Nothing listens on external interfaces
- **WHEN** the stack is up
- **THEN** no published port is bound to 0.0.0.0 (checked by `harness-check`)

### Requirement: Agent visibility through MCP
The repository SHALL ship a project `.mcp.json` that gives a coding agent read-only access to the local database and to logs, traces and metrics.

#### Scenario: Agent reads the database
- **WHEN** the stack is up and the agent calls the postgres MCP to list tables
- **THEN** it gets a result, and a write statement is rejected

#### Scenario: Agent finds a log line
- **WHEN** `harness-check` emits a tagged OTLP log record
- **THEN** a Loki query through Grafana returns that record

### Requirement: Mock upstream records requests
The stack SHALL include a mock upstream API whose received requests can be queried by tests.

#### Scenario: Request journal
- **WHEN** a client calls `http://127.0.0.1:8089/echo`
- **THEN** `GET /__admin/requests` lists that request with its headers
