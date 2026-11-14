# Spec Delta

## Purpose

Stops AI agents, before execution, from reading secret-bearing files, dumping environments, or sending secrets to the model.

## ADDED Requirements

### Requirement: Block secret file reads
Agent requests to read secret-bearing files, by name pattern or because their content contains an active vault secret, SHALL be denied before execution.

#### Scenario: cat .env
- **WHEN** Claude Code requests the Bash command `cat .env`
- **THEN** the hook denies it with a reason and suggests `smith ls` or `smith run`

#### Scenario: Read tool on secret content
- **WHEN** an agent requests to read `config/local.yml` that contains the value of a vault secret
- **THEN** the read is denied and the reason names the matching key without its value

### Requirement: Block environment dumps
Commands that print the whole environment or another process's environment SHALL be denied, including when nested in pipes, subshells or `sh -c` strings.

#### Scenario: Nested printenv
- **WHEN** an agent requests `bash -c "printenv | grep KEY"`
- **THEN** the request is denied

### Requirement: Honest blocking
A blocked action SHALL be reported to the agent as blocked by Locksmith, with a non-success result and a suggested alternative. It SHALL never be reported as success with fabricated output.

#### Scenario: Agent sees block
- **WHEN** a command is denied
- **THEN** the agent receives a failure containing "Blocked by Locksmith" and an alternative command

### Requirement: Ambiguous commands go to the human
Commands that cannot be analysed reliably SHALL result in an ask decision where the agent supports it.

#### Scenario: eval
- **WHEN** an agent requests `eval "$(echo Y2F0IC5lbnY= | base64 -d)"`
- **THEN** the user is asked to approve and the event is audited

### Requirement: Prompt secret interception
A user prompt containing the value of an active vault secret, in any supported encoding, SHALL be blocked before it is sent to the model, and the user SHALL be told which key matched.

#### Scenario: Pasted key
- **WHEN** the user pastes the Stripe key into a Claude Code prompt
- **THEN** the prompt is not submitted and the message names `STRIPE_KEY`

### Requirement: Safe failure
If the Locksmith hook cannot run, the agent action SHALL be blocked with an instruction to run `smith doctor`.

#### Scenario: Binary missing
- **WHEN** `smith` is not on PATH and a hook fires
- **THEN** the action is blocked with a message naming `smith doctor`
