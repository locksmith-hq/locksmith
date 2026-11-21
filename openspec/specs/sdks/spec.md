# sdks Specification

## Purpose

Client libraries for the Locksmith control-plane API, generated from its OpenAPI spec so they never drift, and the remote Hub MCP setup that `smith init` writes for supported agents.

## Requirements

### Requirement: SDK generated from the OpenAPI spec
The TypeScript SDK `@locksmith/sdk` SHALL derive every request and response type from `services/control-plane/openapi.json`, and the repository SHALL fail its tests when the committed generated types differ from a fresh generation.

#### Scenario: Spec changes without regeneration
- **WHEN** an operation is added to `openapi.json` and `packages/sdk` is not regenerated
- **THEN** the SDK drift test (`npm test --workspace packages/sdk`) fails and names the regenerate command

#### Scenario: Every operation is callable
- **WHEN** the SDK test enumerates the spec's `operationId`s
- **THEN** each one has a typed call path through the SDK client

### Requirement: SDK auth and errors
The SDK SHALL send the caller's bearer token on every request, SHALL surface non-2xx responses as a typed error carrying the HTTP status and the RFC 9457 problem fields, and SHALL never log, cache or persist a response body.

#### Scenario: Problem response
- **WHEN** the API answers `403` with a problem document
- **THEN** the SDK throws an error with `status` 403 and the problem's `type` and `title`, and writes nothing to the console

#### Scenario: Enrollment secret stays with the caller
- **WHEN** `createAgent` returns an enrollment secret
- **THEN** the secret is present only in the returned object, and a test asserts that no logger, storage or cache received it

### Requirement: No value routes
The SDK SHALL NOT expose any call to a secret value or key-material route.

#### Scenario: Value routes absent
- **WHEN** the SDK test scans the generated client surface
- **THEN** no exported method targets a path matching the value or key-material route denylist that `packages/sdk` defines from the OpenAPI spec and exports as `VALUE_ROUTE_DENYLIST` (the console leak check, `t3-console-mvp` task 6.2, does not exist yet and can reuse it)

### Requirement: Single client package
`packages/control-plane-client` SHALL use the SDK for its types and requests and SHALL contain no hand-written `fetch` call.

#### Scenario: Apps keep working
- **WHEN** `npm test --workspace apps/web`, `npm test --workspace apps/desktop` and `just apps-build` run after the switch
- **THEN** they pass with no import changes in the apps

### Requirement: Remote Hub MCP entry
`smith init --hub <url>` SHALL write a remote Streamable HTTP MCP entry pointing at `<url>/mcp` for each detected agent that supports remote MCP with OAuth, SHALL write no token or secret into any config file, and SHALL be idempotent.

#### Scenario: Supported agent
- **WHEN** `smith init --hub https://hub.example --yes` runs with a supported agent's config present
- **THEN** that config gains one `locksmith-hub` remote entry with the URL and the public client id, and a second run changes nothing

#### Scenario: Unsupported agent
- **WHEN** a detected agent has no remote-MCP-with-OAuth support
- **THEN** no remote entry is written for it and `smith doctor` reports `hub.mcp: unsupported` for that agent

#### Scenario: No secret in config
- **WHEN** the generated integration files and a test config written by `smith init --hub` are scanned
- **THEN** they contain no bearer token, client secret or canary value
