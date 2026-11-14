# Spec Delta

## Purpose

Gives users a graphical way to set up Locksmith, oversee agent sessions, approve requests and review audit history.

## ADDED Requirements

### Requirement: Secure value entry
Secret values entered in the desktop app SHALL go from a native secure input directly to the daemon and SHALL NOT be readable by the app's web UI layer.

#### Scenario: Add secret
- **WHEN** the user adds a secret through the app
- **THEN** the web layer's state and logs contain no part of the value

### Requirement: Session oversight
The app SHALL show active sessions with their scopes and expiry and SHALL allow revoking any session, with or without killing its processes.

#### Scenario: Revoke from tray
- **WHEN** the user clicks Revoke on a session in the tray menu
- **THEN** the session is revoked and disappears from the list within 1 second

### Requirement: Approval center
Pending approvals from MCP requests, hook ask decisions and biometric step-ups SHALL be shown with their origin, and agent-provided text SHALL be visibly marked as untrusted.

#### Scenario: Pending request badge
- **WHEN** an agent requests a secret
- **THEN** the tray icon shows a badge and the approval center shows the request

### Requirement: Guided onboarding
First launch SHALL guide the user through vault creation, recovery phrase confirmation, optional biometric enrollment and first project setup.

#### Scenario: First run
- **WHEN** the app starts with no vault
- **THEN** the onboarding flow starts and ends with a working project with hooks installed
