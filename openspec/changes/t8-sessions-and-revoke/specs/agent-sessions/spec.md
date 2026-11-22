# Spec Delta

## Purpose
Lets an org member see live agent sessions and cut agent access quickly, with the gateway enforcing it within seconds.

## ADDED Requirements

### Requirement: Live sessions are listed without values
The control plane SHALL list an org's live agent sessions with agent id and name, kind, binding slug, start time and last-seen time, and SHALL never include a token, secret value or upstream address.

#### Scenario: Admin lists sessions
- **WHEN** an org member requests the sessions list while two agents hold open sessions
- **THEN** both appear with slugs and times, and the response contains no token or value

#### Scenario: Session ends
- **WHEN** the gateway reports a session closed or stops reporting it for longer than three times the heartbeat interval (15 seconds)
- **THEN** it no longer appears as live

### Requirement: Revoke one or all sessions
An authorized org member SHALL be able to revoke one session or all sessions of the org, and each action SHALL append a ledger event naming the actor.

#### Scenario: Revoke one
- **WHEN** an org member revokes a session
- **THEN** the gateway closes it and refuses that session's token within 10 seconds, and `session.revoked` is in the ledger

#### Scenario: Revoke all
- **WHEN** an org member revokes all sessions
- **THEN** every live session of the org closes within 10 seconds; new sessions from the same agents still work if their grants do

### Requirement: Pause and resume every agent
An authorized org member SHALL be able to pause all agents of an org. While paused, the gateway SHALL refuse every agent request and open session before decrypting anything, and SHALL record `db.session.denied` or the equivalent denial event. Resume SHALL restore normal grant checks.

#### Scenario: Pause during use
- **WHEN** an org member pauses agents while a session is live
- **THEN** the session closes and further requests are refused within 10 seconds, with no decrypt

#### Scenario: Resume
- **WHEN** an org member resumes agents
- **THEN** requests with valid grants succeed again without re-enrolment

### Requirement: Authorized and fail closed
Only signed-in members of the org (the same authorization as revoking a grant) SHALL list, revoke or pause; others get `403`. If the gateway cannot read the pause or revoke state, it SHALL deny rather than allow.

#### Scenario: Non-member
- **WHEN** a caller outside the org requests revoke or pause
- **THEN** the response is `403` and nothing changes

#### Scenario: Control plane unreachable
- **WHEN** the gateway cannot refresh revoke and pause state past its cache TTL
- **THEN** agent requests are denied
