# Spec Delta

## Purpose

Defines how Locksmith runs on a user's own machine or cluster from released images, a compose bundle or a Helm chart, with secrets generated on the host and honest labels about what the setup protects.

## ADDED Requirements

### Requirement: Released container images
The release SHALL publish container images for the control plane and the gateway for linux/amd64 and linux/arm64, running as a non-root user, each tagged with the release version and its digest recorded in the release notes.

#### Scenario: Image runs unprivileged
- **WHEN** a built image is inspected and started
- **THEN** its configured user is not root, it has no shell secrets baked in, and the service answers its health endpoint

#### Scenario: No secret in an image
- **WHEN** the leak scan and an image-layer scan run over the built images
- **THEN** no canary or dev-only token from `infra/compose/compose.yaml` is found

### Requirement: One-command compose self-host
The compose bundle SHALL start Postgres 18, the key provider, the control plane and the gateway with a single documented command, and wait until every service is healthy.

#### Scenario: Clean host start
- **WHEN** the one command runs on a host with Docker and no previous state
- **THEN** all services report healthy, migrations are applied, and an API request through the gateway to a test upstream succeeds

#### Scenario: Restart keeps data
- **WHEN** the stack is stopped and started again
- **THEN** existing data and keys are still usable and no secret is regenerated

### Requirement: Secrets are generated on the host
First run SHALL generate every password, token and key-provider credential with a cryptographically secure generator into a mode 0600 file outside version control, and SHALL NOT print their values, log them or reuse the fixed dev-only values.

#### Scenario: Generated and hidden
- **WHEN** the first run completes
- **THEN** the secrets file exists with mode 0600, differs between two fresh runs, and no secret value appears in the command output or container logs

#### Scenario: Dev values refused
- **WHEN** the bundle is started with any of the known dev-only default values in its settings
- **THEN** startup fails with a message naming the setting, not the value

### Requirement: Key custody is labelled honestly
The bundle SHALL document its key-provider mode and label the protection it gives as containment, and SHALL support pointing the services at an operator-run key provider instead of the bundled one.

#### Scenario: External key provider
- **WHEN** the operator sets the external key provider address and credential reference
- **THEN** the bundled key provider is not started and the services use the external one

### Requirement: Helm chart takes references, not values
The Helm chart SHALL install the control plane, the gateway and a migration job, and SHALL read the database connection, OIDC settings and key-provider credential only from names of existing Kubernetes Secrets, never from chart values.

#### Scenario: Install on kind
- **WHEN** `helm install` runs on a local kind cluster with the prerequisite Secrets created
- **THEN** pods become ready, the migration job completes, and the same smoke request as the compose bundle succeeds

#### Scenario: Value rejected
- **WHEN** a values file supplies a literal password or token field
- **THEN** `helm lint` or the chart's values schema rejects it

#### Scenario: Pod hardening
- **WHEN** the rendered manifests are checked
- **THEN** pods run as non-root with a read-only root filesystem and dropped capabilities, and the manifests pass schema validation

### Requirement: TLS and sign-in are the operator's choice
The compose bundle SHALL offer an optional TLS reverse-proxy profile and an optional demo OIDC issuer profile, and SHALL accept any OIDC issuer URL; the demo issuer SHALL be labelled not for production.

#### Scenario: Own issuer
- **WHEN** an OIDC issuer URL is configured and the demo profile is off
- **THEN** the control plane validates tokens against that issuer and no demo issuer container runs

### Requirement: Self-host never depends on us
The images, compose bundle and chart SHALL start and run with no call to any Locksmith-operated service, and licensing, billing or update-check failures SHALL NOT block start, unlock or export.

#### Scenario: Offline start
- **WHEN** the stack starts with outbound network access to Locksmith-operated hosts blocked
- **THEN** it reaches healthy and export still works
