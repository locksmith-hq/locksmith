# Spec Delta

## Purpose

Defines the team secrets platform in which secret values are never present on the machine where an agent runs.

## ADDED Requirements

### Requirement: Agents never hold secrets
For an agent identity the platform SHALL never deliver a secret value to the agent host; use of a secret SHALL happen only through a gateway, a delegated credential flow, or a short-lived scoped credential.

#### Scenario: Agent calls an API
- **WHEN** an agent with a grant calls an upstream API through the gateway
- **THEN** the gateway attaches the credential, the agent receives only the response with the secret redacted, and no process on the agent host holds the value

#### Scenario: Agent asks for a value
- **WHEN** an agent or its connector asks the control plane for a secret's value
- **THEN** the request is refused and audited

### Requirement: The control plane cannot decrypt secrets
Secret versions SHALL be stored only as ciphertext with data keys wrapped to authorised gateways and recovery keys; the control plane SHALL hold no key able to decrypt them.

#### Scenario: Database dump
- **WHEN** an attacker obtains the full control-plane database and its secrets
- **THEN** no secret value can be recovered without a gateway or recovery private key

### Requirement: Policy-owned destinations
The hosts and paths a secret may be sent to SHALL be set by authorised humans in platform policy and SHALL NOT be derivable from agent-controlled input.

#### Scenario: Agent proposes a new host
- **WHEN** an agent requests access to a host not in policy
- **THEN** the gateway refuses it and the agent may file an access proposal that a human must approve

### Requirement: Revocation is prompt
Revoking an agent identity, session or secret grant SHALL stop gateway use within the configured token TTL and, for connected gateways, within seconds.

#### Scenario: Kill switch
- **WHEN** an admin revokes an agent
- **THEN** subsequent gateway requests with its tokens are refused and the event is audited

### Requirement: Open and self-hostable
The server components SHALL be available under an open-source licence and runnable by a customer with a single command, including their own gateways.

#### Scenario: Self-host
- **WHEN** an operator runs the documented compose file
- **THEN** a working control plane, gateway and console start with no licence key or network call to Locksmith services
