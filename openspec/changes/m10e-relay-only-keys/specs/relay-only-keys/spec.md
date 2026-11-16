# Spec Delta

## Purpose

Makes the relay the only path by which an agent-started session can use a key it was not explicitly allowed to inject, and puts the relay's destinations under human control.

## ADDED Requirements

### Requirement: Relay-only keys
For a session started by an agent (`AgentSessionStart`), the daemon SHALL refuse to inject any key into a command environment unless the agent policy lists it in `inject` for the session's project.

#### Scenario: Key not in the inject list
- **WHEN** an agent session runs `smith run --only LANGFUSE_PI_SECRET_KEY` and the policy's `inject` list for the project does not contain it
- **THEN** the run is refused with a message naming the key and saying it is relay-only, nothing is injected, and the audit records `BLOCKED relay_only` with the key name and no value

#### Scenario: Mixed request
- **WHEN** a run asks for one allowed and one relay-only key
- **THEN** the whole run is refused and no key is injected

#### Scenario: Human-started session
- **WHEN** a human starts a session with `smith session start`
- **THEN** relay-only does not apply

### Requirement: Policy-owned relay hosts
For a session started by an agent, the hosts a key may be relayed to SHALL come from the agent policy, not from `.locksmith.toml`.

#### Scenario: Agent edits the binding
- **WHEN** the agent adds an extra host to a key's hosts in `.locksmith.toml` before starting a session
- **THEN** requests to that host through the relay are refused and audited `BLOCKED relay_host`, and the key value is not sent

### Requirement: Relay network guard
The relay SHALL refuse upstream connections to loopback, private, link-local, carrier-grade NAT, unspecified and cloud-metadata addresses unless the policy allows the exact target, and SHALL connect to the address it checked.

#### Scenario: DNS rebinding
- **WHEN** an allowed hostname resolves to a public address at check time and a private one at a later lookup
- **THEN** the relay connects only to the checked address, or refuses if it was blocked

#### Scenario: Metadata endpoint
- **WHEN** a policy host resolves to `169.254.169.254`
- **THEN** the connection is refused even if the policy allowlists private ranges

### Requirement: Responses never carry the key
The relay SHALL redact the injected key value from response headers and bodies before they reach the agent.

#### Scenario: Echo upstream
- **WHEN** the upstream reflects the Authorization header in its response body
- **THEN** the agent receives the redaction marker, not the value, including for compressed and chunk-split bodies

### Requirement: Extraction attempts find nothing
For a key outside `inject`, no agent-reachable path SHALL reveal its value.

#### Scenario: Canary extraction suite
- **WHEN** the encoding probe (plain, reversed, spaced, split, base64, hex, ROT13, character codes) is run under an agent session for the `TEST` canary, and relay calls are made to policy hosts and non-policy hosts
- **THEN** no output contains the canary or a transformation of it
