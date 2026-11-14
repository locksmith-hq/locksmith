# Spec Delta

## Purpose

Lets agents and their programs call AWS APIs while long-lived AWS credentials stay inside Locksmith and every call is checked against project policy.

## ADDED Requirements

### Requirement: Delegated signing
Within a session configured for AWS, AWS CLI and SDK requests SHALL succeed through Locksmith using only session-scoped dummy credentials available to the agent.

#### Scenario: S3 list
- **WHEN** the agent runs `aws s3 ls s3://app-bucket` inside the session
- **THEN** the listing is returned and an AWS ACCESS event names the service, action and resource

#### Scenario: Export credentials
- **WHEN** the agent runs `aws configure export-credentials`
- **THEN** only the session dummy credentials are shown

### Requirement: Policy enforcement
The relay SHALL deny AWS actions or resources not allowed by the project policy, and SHALL deny unknown actions by default.

#### Scenario: Write denied by default
- **WHEN** the policy is the read-only default and the agent runs `aws s3 rm s3://app-bucket/x`
- **THEN** the call fails with an access-denied style error and a BLOCKED event is audited

### Requirement: Outsider requests rejected
Requests not signed with the current session's dummy credentials SHALL be rejected.

#### Scenario: Stolen dummy keys used after revoke
- **WHEN** the session is revoked and a request signed with its dummy keys arrives
- **THEN** the relay rejects it

### Requirement: Contained fallback is labelled
When temporary credentials are issued to a process, they SHALL be limited to 15 minutes and to the project policy as an STS session policy, and the command SHALL state that the credentials are visible to that process.

#### Scenario: Contained credentials
- **WHEN** the user runs `smith aws creds --contained -- terraform plan`
- **THEN** terraform receives credentials expiring within 15 minutes and the console shows the containment notice
