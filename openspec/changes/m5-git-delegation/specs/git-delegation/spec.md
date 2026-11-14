# Spec Delta

## Purpose

Lets agents clone, fetch and push private repositories while the upstream Git credential stays inside Locksmith.

## ADDED Requirements

### Requirement: Transparent Git transport
After `smith git setup`, Git operations against configured hosts using HTTPS or SSH remote URLs SHALL succeed through Locksmith without the user or agent supplying credentials.

#### Scenario: Push from session
- **WHEN** an agent in an active session runs `git push origin feature`
- **THEN** the push succeeds and a Git ACCESS event is audited

### Requirement: Upstream credential never disclosed
No command, file, environment variable, credential helper output or network response available to the session SHALL contain the upstream Git credential.

#### Scenario: credential fill
- **WHEN** an agent runs `git credential fill` for github.com
- **THEN** the output contains only a session-scoped Locksmith token and not the upstream token

### Requirement: Forwarder bound to session
The forwarder SHALL serve only requests carrying a valid session token from processes inside that session's tree.

#### Scenario: Token replay from outside
- **WHEN** a process outside the session tree replays a captured forwarder token
- **THEN** the request is rejected with HTTP 403 and a BLOCKED event is audited

#### Scenario: After revoke
- **WHEN** the session is revoked
- **THEN** subsequent Git operations through the forwarder fail

### Requirement: Minimal upstream scope
When a GitHub App is configured, Locksmith SHALL use installation tokens limited to the single target repository and to contents, pull request and metadata permissions.

#### Scenario: Other repo
- **WHEN** an agent pushes to a repository not in the project's allowlist
- **THEN** the push is rejected by Locksmith before contacting the upstream

### Requirement: Protected ref policy
The forwarder SHALL reject pushes that delete or overwrite a stale value of a ref marked protected in the project binding.

#### Scenario: Delete main
- **WHEN** an agent runs `git push origin :main` with main protected
- **THEN** the push fails with a message naming the policy rule
