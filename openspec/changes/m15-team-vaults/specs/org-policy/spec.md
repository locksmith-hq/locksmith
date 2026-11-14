# Spec Delta

## Purpose

Lets organisations enforce consistent agent-credential rules across all members' machines and review all agent access centrally.

## ADDED Requirements

### Requirement: Signed org policy
Members' daemons SHALL apply the latest org policy signed by an org admin key, SHALL reject unsigned or older policy versions, and SHALL combine it with local settings by taking the stricter value per field.

#### Scenario: TTL cap
- **WHEN** org policy caps leases at 4 hours and a user requests 8
- **THEN** the session is created with a 4-hour expiry and the user is told why

### Requirement: Central audit
Members' audit events SHALL be delivered encrypted to the organisation's audit key and SHALL be viewable by admins as a merged timeline.

#### Scenario: Admin view
- **WHEN** a member's agent accesses a shared secret
- **THEN** the admin timeline shows the event within 1 minute when the member is online
