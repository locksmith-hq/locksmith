# Spec Delta

## Purpose

Defines the HTTP API served by NestJS, the boundary with the Rust core, and the rule that an endpoint moves from the Rust control plane only when it behaves identically.

## ADDED Requirements

### Requirement: Contract parity before cut-over
A path SHALL be served by the NestJS API only after the recorded contract tests for it pass against NestJS with the same status codes, response bodies and error shapes as the Rust control plane, and `openapi.json` is unchanged or changed only with the `breaking-api` rule.

#### Scenario: A module passes the contract
- **WHEN** the contract runner replays the recorded requests for a path against the NestJS API
- **THEN** every response matches the Rust recording and the route table may switch that path to `nest`

#### Scenario: A module diverges
- **WHEN** a replayed response differs from the recording
- **THEN** the runner fails naming the path and the first differing field, and the path stays on `rust`

### Requirement: Tenant isolation holds in the NestJS API
Every request SHALL run in one transaction that sets `app.org_id` with `set_config(..., true)` before any query, as an application role that is neither table owner nor `BYPASSRLS`.

#### Scenario: Cross-tenant read is empty
- **WHEN** org A's token requests a resource id that belongs to org B
- **THEN** the API answers not found, exactly as the Rust control plane does

#### Scenario: Context is per transaction
- **WHEN** two concurrent requests from different orgs share a pooled connection
- **THEN** neither sees the other's rows

### Requirement: No plaintext secret or key material in the NestJS process
The NestJS API SHALL NOT receive, hold, log or return a plaintext secret value or key bytes; operations that need them SHALL call the Rust core.

#### Scenario: Secret write carries ciphertext only
- **WHEN** a client writes a secret version
- **THEN** the API accepts a sealed ciphertext envelope and rejects a plaintext body

#### Scenario: Leak scan
- **WHEN** `just leak-scan` runs after the API's test suite with canary secrets in the fixtures
- **THEN** no canary appears in the API's logs, traces or database

### Requirement: TypeScript quality gates
Every TypeScript package SHALL pass oxlint, oxfmt check, knip and the type check in CI through Turborepo.

#### Scenario: Unused export
- **WHEN** a package exports a symbol nothing imports
- **THEN** knip fails the PR and names the file
