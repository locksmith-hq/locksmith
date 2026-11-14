# Spec Delta

## Purpose

Gives agents and their tools a local database endpoint that needs no password, while Locksmith authenticates to the real database.

## ADDED Requirements

### Requirement: Password-less local endpoint
`smith db connect <name>` SHALL expose a local endpoint for the named Postgres, MySQL or Redis target, accepting clients from the session without a password.

#### Scenario: Migration
- **WHEN** the agent runs a migration tool against the local endpoint
- **THEN** the migration runs against the real database using the vault credential

### Requirement: Password never disclosed
The database password or client key SHALL NOT appear in any environment variable, file, connection banner or error message available to the session.

#### Scenario: Inspect everything
- **WHEN** the agent inspects env, config files, `ss -tp` output and server error messages
- **THEN** the oracle finds no encoding of the password

### Requirement: Session-bound listener
The relay SHALL accept only connections from processes inside the authorized session tree and SHALL close all relayed connections when the session is revoked.

#### Scenario: Revoke closes connections
- **WHEN** the session is revoked during a long-running query
- **THEN** the relayed connection is closed within 1 second
