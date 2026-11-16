# Spec Delta

## ADDED Requirements

### Requirement: Session source
The daemon SHALL record for every lease, at start, a source (kind and label) and an optional host derived only from executable paths the kernel reports for the lease root and its ancestors (for a human-started lease, the source from the agent command), SHALL NOT read process arguments or environment for it, and SHALL NOT use it for any authorization decision.

#### Scenario: Known agent
- **WHEN** an agent-started lease is rooted at a process whose executable is `claude`, running under iTerm2
- **THEN** the lease shows source `claude_code_cli` ("Claude Code") and host `iTerm2`

#### Scenario: Claude Code inside the desktop app
- **WHEN** the root executable lies under `Library/Application Support/Claude/claude-code/` or inside `/Applications/Claude.app`
- **THEN** the source is `claude_desktop_app`

#### Scenario: Unrecognized or renamed binary
- **WHEN** the root executable is `node` or `my-claude`
- **THEN** the source is `other` labelled with that executable name, and no known kind is guessed

#### Scenario: Unreadable root
- **WHEN** the root executable path cannot be read
- **THEN** the source is `unknown`

#### Scenario: Hostile process name
- **WHEN** the root executable name contains control characters or is very long
- **THEN** the stored label has the control characters removed and is at most 64 characters

### Requirement: Self-reported agent and model
The daemon SHALL accept optional `agent` and `model` strings on an agent session start, SHALL reject a value that is empty, longer than 64 bytes or not printable ASCII with BadRequest, SHALL store accepted values on the lease marked as self-reported and record them in the SESSION_START audit row, and SHALL NOT use them for any authorization decision.

#### Scenario: Reported model
- **WHEN** the agent starts an in-policy session with agent `claude-code` and model `claude-fable-5-2`
- **THEN** the lease reports them with `reported: true` and the SESSION_START audit row contains `reported agent="claude-code" model="claude-fable-5-2"`

#### Scenario: Invalid value
- **WHEN** the model contains a control character or exceeds 64 characters
- **THEN** the request fails with BadRequest and no lease is created

#### Scenario: Older client
- **WHEN** a session start request without `agent` and `model` arrives
- **THEN** it is handled as before, with no report on the lease

### Requirement: Lease origin in status
Session status SHALL include for each lease its root pid and executable, who started it (`human` or `agent`), source, host, self-report, project, environment, scopes, creation and expiry times and state, and SHALL carry no secret material.

#### Scenario: Status lists origin
- **WHEN** the user runs `smith status --json` during an agent-started session
- **THEN** each session entry includes `started_by`, `source`, `host`, `report` and `root_exe`

#### Scenario: Status from an older daemon
- **WHEN** a client reads a status without the new fields
- **THEN** it parses, with source `unknown` and `started_by` `human`
