## ADDED Requirements

### Requirement: Gateway streams Git smart HTTP with an injected credential
The gateway SHALL expose `/git/<host>/<owner>/<repo>.git/...` for the smart-HTTP endpoints (`info/refs`, `git-upload-pack`, `git-receive-pack`), stream request and response bodies without buffering them whole, and add the bound credential to the upstream request. The caller SHALL never receive the credential.

#### Scenario: Clone and push through the gateway
- **WHEN** an agent with a grant runs `git clone` then commits and `git push` through the gateway against a local smart-HTTP fixture that requires the injected credential
- **THEN** both succeed, the fixture saw the credential on every request, and the agent environment, config and process arguments never contain it

#### Scenario: Large body is streamed
- **WHEN** a push of at least 50 MB is sent through the gateway
- **THEN** it succeeds and gateway memory stays bounded (no body is held whole)

### Requirement: Binding limits host, repository and service
A Git credential SHALL be injected only for the bound host and repository path prefix, and only for the services the grant allows (`fetch`, `push`).

#### Scenario: Unbound repository
- **WHEN** the agent addresses a repository outside the binding
- **THEN** the gateway returns 403, makes no upstream call and no decrypt call

#### Scenario: Push without push grant
- **WHEN** a fetch-only grant is used for `git-receive-pack`
- **THEN** the gateway returns 403 and records a denied ledger event

#### Scenario: Redirect is not followed
- **WHEN** the upstream answers with a redirect to another host
- **THEN** the gateway does not follow it and does not resend the credential

### Requirement: No credential in Git output or the ledger
Upstream headers and error text returned to the caller SHALL be redacted of the credential in every form the relay redactor covers, and ledger events SHALL record host, repository, service and outcome but never the credential or the pack data.

#### Scenario: Upstream echoes the credential in an error
- **WHEN** the upstream error body or header contains the credential
- **THEN** the caller sees a redaction marker and `redaction_failed` is recorded if it cannot be removed
