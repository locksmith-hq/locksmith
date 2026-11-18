# Spec Delta

## MODIFIED Requirements

### Requirement: Every relay call is audited
Each relay attempt, allowed or refused, SHALL append its records to the org's audit ledger, naming the secret id, version, agent id, upstream host, status and outcome, and never the value, headers or the full URL query. An allowed call SHALL record an `attempt` event before any key unwrap and an `outcome` event after the upstream call. If the `attempt` event cannot be appended, the gateway SHALL refuse the call without unwrapping a key or calling the upstream. `gateway_audit` SHALL receive no new rows.

#### Scenario: Audit events per call
- **WHEN** one allowed and one refused call are made
- **THEN** the org's ledger gains `attempt` and `outcome` events with outcome `ok` for the allowed call and a `denied` event for the refused call, `gateway_audit` gains no rows, and no event contains the canary

#### Scenario: Ledger unavailable
- **WHEN** the control-plane audit append endpoint is unreachable or returns an error
- **THEN** the relay returns 503, the KMS stand-in records no decrypt call, and the mock upstream receives no request
