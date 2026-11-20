# Spec Delta

## Purpose
The signed-in web console: a person manages projects, environments, secret names, agents, grants and activity through the control-plane API, without the console ever handling a secret value.

## ADDED Requirements

### Requirement: Signed-in shell
The console SHALL require a signed-in session before showing any page and SHALL send the user's bearer token on every API call.

#### Scenario: Signed-out visit
- **WHEN** a visitor opens any console route without a session
- **THEN** the first sign-in screen is shown and no API data request is made

#### Scenario: Expired session
- **WHEN** the API answers `401` to a console request
- **THEN** the console returns to the sign-in screen and keeps no stale data on screen

### Requirement: Hub overview and checklist
The console SHALL open on an Overview showing counts of projects, agents and recent activity, and a dismissible "Get started" checklist on first run.

#### Scenario: First run
- **WHEN** a newly created user lands after sign-in
- **THEN** the Overview shows the personal org name and the checklist, and dismissing it persists across reloads

### Requirement: Projects and environments management
The console SHALL list, create, rename and delete projects and their environments through the API and show the API's error when it refuses.

#### Scenario: Create a project
- **WHEN** the user submits a new project name
- **THEN** the project appears in the list after the API confirms it

#### Scenario: API refusal
- **WHEN** the API answers `403` or `409` to a change
- **THEN** the page shows the problem title and leaves the list unchanged

### Requirement: Secret names without values
The console SHALL show each secret's name, versions, key ids and creation times, and MUST NOT display, request or store any secret value.

#### Scenario: Secret detail
- **WHEN** the user opens a secret
- **THEN** only metadata is shown and no network request targets a value or material route

### Requirement: Agents and grants management
The console SHALL list agents, register and revoke them, and create and revoke grants, showing each grant's mode, target and expiry.

#### Scenario: Revoke a grant
- **WHEN** the user confirms revoking a grant
- **THEN** the grant disappears from the list and the Activity page later shows the revocation event

### Requirement: One-time enrollment secret
The console SHALL show an agent's enrollment secret only once, in the dialog that received it, and MUST NOT keep it in the query cache, browser storage, logs or error reports.

#### Scenario: Register an agent
- **WHEN** the API returns an enrollment secret for a new or rotated agent
- **THEN** it is shown once with a copy action, and closing the dialog clears it from memory, cache and storage

### Requirement: Activity view
The console SHALL show audit events newest first with paging and the ledger verification status, without payload values.

#### Scenario: Ledger status
- **WHEN** the Activity page loads
- **THEN** it shows whether the ledger verified and lists the latest events

### Requirement: Honest page states
Every console page SHALL show distinct loading, empty and error states.

#### Scenario: Server error
- **WHEN** a list request fails with a network or `5xx` error
- **THEN** the page shows an error state with a retry action and no empty-state message
