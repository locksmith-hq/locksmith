# control-plane-api Specification

## Purpose
The control plane's tenant-scoped REST API: orgs, projects, environments and secret metadata, with strict org isolation and a published OpenAPI contract that later changes extend.

## Requirements

### Requirement: Versioned resource API
The service SHALL expose JSON resources under `/v1`. An org contains projects; a project contains environments; secret metadata belongs to one project and one environment. Every resource SHALL have a UUIDv7 `id` and `created_at` and `updated_at` timestamps in RFC 3339 UTC. Names SHALL be unique within their parent: project names within an org, environment names within a project, and secret names within a project and environment.

#### Scenario: Create and read a project tree
- **WHEN** a client creates an org, a project in it, an environment `dev` in the project, and a secret named `STRIPE_KEY` in `dev`
- **THEN** each create returns `201` with the new resource and a `Location` header, and a GET on each location returns the same resource

#### Scenario: Duplicate name is rejected
- **WHEN** a client creates a second environment named `dev` in the same project
- **THEN** the response is `409` and no second environment exists

#### Scenario: IDs are time-ordered
- **WHEN** two projects are created one after another
- **THEN** the second project's `id` sorts after the first

### Requirement: Secret metadata never carries a value
In this version, the secret resource SHALL hold metadata only: name, description, timestamps and `version_count`. No request field SHALL accept a secret value, and no response, log line or trace attribute SHALL contain one.

#### Scenario: Value field is rejected
- **WHEN** a client sends a secret create request that includes a `value` field
- **THEN** the response is `400` naming the unknown field, and nothing is stored

#### Scenario: No canary in telemetry
- **WHEN** a canary string is used as a secret description and the e2e suite runs
- **THEN** `just leak-scan` finds the canary only in the database's description column and nowhere in logs or traces
- **AND** the scan does not count the description as a leak, because descriptions are not secret

### Requirement: Org isolation
Every request that touches tenant data SHALL be bound to exactly one org, and the database SHALL enforce that binding. A request for another org's resource SHALL behave as if the resource did not exist.

#### Scenario: Cross-org read
- **WHEN** a client bound to org A requests a project id that belongs to org B
- **THEN** the response is `404`, the same as for an id that does not exist

#### Scenario: Cross-org list
- **WHEN** a client bound to org A lists projects
- **THEN** no project from org B appears

#### Scenario: Request without an org
- **WHEN** a request to a tenant resource carries no org binding
- **THEN** the response is `401` and no query runs

### Requirement: Dev-only org binding
Until human sign-in exists, the org MAY be selected with the `X-Locksmith-Dev-Org` header, but only when dev auth is enabled. With dev auth enabled, the service SHALL refuse to start unless every listen address is loopback.

#### Scenario: Dev auth on a public bind
- **WHEN** the service starts with dev auth enabled and a non-loopback listen address
- **THEN** it exits non-zero before it accepts connections, with a message naming the setting

#### Scenario: Dev header ignored when dev auth is off
- **WHEN** dev auth is disabled and a request carries `X-Locksmith-Dev-Org`
- **THEN** the response is `401`

### Requirement: Errors and pagination
Errors SHALL use RFC 9457 problem details (`application/problem+json`) with a stable `type` URI, and SHALL never echo request bodies. List endpoints SHALL paginate with an opaque `next` cursor and a `limit` of at most 100.

#### Scenario: Validation error shape
- **WHEN** a client creates a project with an empty name
- **THEN** the response is `400` with `content-type: application/problem+json` and a `type` that identifies a validation error

#### Scenario: Cursor pagination
- **WHEN** an org has 120 projects and the client lists them with `limit=50`, following `next` until it is absent
- **THEN** it receives all 120 exactly once, in creation order

### Requirement: Published OpenAPI contract
The service SHALL serve its OpenAPI 3.1 document at `/openapi.json`. The repository SHALL hold a committed copy, and a test SHALL fail when the served document differs from it.

#### Scenario: Contract drift
- **WHEN** a route or schema changes and the committed `openapi.json` is not updated
- **THEN** the OpenAPI snapshot test fails and names the difference
