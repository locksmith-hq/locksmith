# gateway-http-relay Specification

## Purpose
The gateway decrypts a stored secret only in its own memory, injects it into one outbound HTTP call for a caller that never receives it, and records the call.

## Requirements

### Requirement: Relay injects the secret without returning it
`POST /v1/relay` SHALL decrypt the referenced secret version inside the gateway, add it to the upstream request using the binding's header template, send the request and return the upstream status, headers and body. The response to the caller SHALL NOT contain the value in any supported encoding.

#### Scenario: Upstream receives the secret
- **WHEN** a caller relays a request bound to a secret to the mock upstream
- **THEN** the mock upstream records the injected header value equal to the secret and the caller gets the upstream status

#### Scenario: Echoed secret is redacted
- **WHEN** the upstream echoes the secret in the body or a header, in plain, base64, URL-encoded or hex form
- **THEN** the caller's response contains a redaction marker and no encoding of the value

### Requirement: Binding restricts where a secret may be sent
A secret SHALL be injected only into requests whose scheme and host match the binding's allowlist. Any other target, including private, loopback and link-local addresses unless explicitly allowed for the mock upstream, SHALL be refused before any key unwrap.

#### Scenario: Disallowed host
- **WHEN** a caller relays to a host not in the binding
- **THEN** the gateway returns 403, makes no upstream call and makes no KMS decrypt call

#### Scenario: Redirect to another host
- **WHEN** the upstream answers with a redirect to a host outside the binding
- **THEN** the gateway does not follow it and does not resend the credential

### Requirement: Only the gateway can decrypt
The gateway SHALL be the only component holding the KMS decrypt credential. The control-plane material endpoint SHALL return only ciphertext, the wrapped DEK and the key id, and SHALL require the gateway service token. `/v1/relay` SHALL require a valid agent token (signature, audience, expiry) and an unexpired grant for the requested secret.

#### Scenario: Material endpoint carries no plaintext
- **WHEN** the material endpoint is called with a valid service token
- **THEN** the body contains ciphertext and wrapped DEK only, and a request without the token gets 401

#### Scenario: Caller authentication
- **WHEN** `/v1/relay` is called without a valid agent token
- **THEN** it returns 401 and performs no fetch, unwrap or upstream call

#### Scenario: Caller without a grant
- **WHEN** `/v1/relay` is called with a valid agent token but no unexpired grant for the secret
- **THEN** it returns 403 and performs no fetch, unwrap or upstream call

### Requirement: Plaintext never leaves the call
The value SHALL exist only in `secrecy`/`zeroize` types, SHALL NOT appear in logs, traces, error messages or database rows, and the DEK cache SHALL expire entries after a bounded TTL.

#### Scenario: Leak scan is clean
- **WHEN** a relay call with a canary secret completes
- **THEN** `just leak-scan` finds no encoding of the canary in Postgres, logs, traces, the gateway's files or the caller transcript

#### Scenario: Failure paths do not leak
- **WHEN** unwrap fails, the upstream is unreachable or the upstream times out
- **THEN** the caller gets a generic error with no secret material and the audit record shows the failure outcome

### Requirement: Every relay call is audited
Each relay attempt, allowed or refused, SHALL append its records to the org's audit ledger, naming the secret id, version, agent id, upstream host, status and outcome, and never the value, headers or the full URL query. An allowed call SHALL record an `attempt` event before any key unwrap and an `outcome` event after the upstream call. If the `attempt` event cannot be appended, the gateway SHALL refuse the call without unwrapping a key or calling the upstream. `gateway_audit` SHALL receive no new rows.

#### Scenario: Audit row per call
- **WHEN** one allowed and one refused call are made
- **THEN** the org's ledger gains `attempt` and `outcome` events with outcome `ok` for the allowed call and a `denied` event for the refused call, `gateway_audit` gains no rows, and no event contains the canary

#### Scenario: Ledger unavailable
- **WHEN** the control-plane audit append endpoint is unreachable or returns an error
- **THEN** the relay returns 503, the KMS stand-in records no decrypt call, and the mock upstream receives no request
