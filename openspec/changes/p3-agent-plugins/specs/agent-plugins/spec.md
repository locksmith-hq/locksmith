# Spec Delta

## Purpose

Defines how Locksmith wires its guardrail hook and MCP server into the supported coding agents from one generated source, so each agent gets the same protection and an honest statement of what that protection is.

## ADDED Requirements

### Requirement: Supported agents are generated from one source
The repo SHALL provide integration files for Gemini CLI, GitHub Copilot, Windsurf, Cline and a generic MCP client, and every hook or MCP config file in them SHALL be generated from `crates/smith-cli/src/agents.rs`.

#### Scenario: Drift is caught
- **WHEN** a generated file under `integrations/` differs from the generator output
- **THEN** `cargo test -p smith-cli --bin smith agents` fails and names the file

### Requirement: Idempotent init for new agents
`smith init` SHALL detect each new agent from its repo markers and merge the Locksmith hook and MCP server into its config, keeping every other setting and an existing `locksmith` entry unchanged.

#### Scenario: Re-running init
- **WHEN** `smith init` runs twice in a repo that has the agent's marker directory
- **THEN** the second run changes no file and unrelated settings are preserved

#### Scenario: Invalid existing config
- **WHEN** the agent's existing config is not valid JSON or TOML
- **THEN** `smith init` reports the error and leaves the file untouched

### Requirement: Hook decisions match across agents
`smith hook <agent> <event>` SHALL accept each new agent's payload and answer in that agent's reply format, using the same decision rules as the existing agents.

#### Scenario: Secret read denied
- **WHEN** a new agent's hook payload asks to read a protected secret file or dump the environment
- **THEN** the reply denies the action in that agent's format and the denial is audited

#### Scenario: Benign action allowed
- **WHEN** the payload is an ordinary command or file read
- **THEN** the reply allows it

### Requirement: Hook fails closed
Each generated hook command SHALL deny visibly when `smith` is not on `PATH`, in the agent's own denial shape.

#### Scenario: smith missing
- **WHEN** the hook command runs with no `smith` on `PATH`
- **THEN** the agent receives a denial that says to run `smith doctor`

### Requirement: Honest protection labels
For an agent without a pre-tool hook, the integration SHALL provide MCP configuration and instructions only, and its README and `smith doctor` SHALL label the protection as detection or none, not prevention.

#### Scenario: Doctor on a hookless agent
- **WHEN** `smith doctor` runs in a repo using an agent without a pre-tool hook
- **THEN** its output states that no preventing hook is available for that agent

### Requirement: Smoke test per integration
Each integration SHALL have a live or recorded smoke test and a `just test <name>` recipe, and a recorded test SHALL name how its fixtures were captured.

#### Scenario: Recipe runs
- **WHEN** `just test gemini-cli` (and `copilot`, `windsurf`, `cline`, `generic-mcp`) runs offline
- **THEN** it runs that integration's tests and exits zero

#### Scenario: No secret in fixtures
- **WHEN** the leak scan runs over the integration files and recorded fixtures
- **THEN** it finds no secret value

### Requirement: Generic MCP setup
The repo SHALL document a setup for any MCP client that runs `locksmith-mcp` over stdio, with the exact snippet and a note that no hook protection applies.

#### Scenario: Snippet valid
- **WHEN** the generic MCP snippet is parsed
- **THEN** it is valid JSON and starts `locksmith-mcp` with no arguments or secrets
