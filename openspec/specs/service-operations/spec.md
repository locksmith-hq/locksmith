# service-operations Specification

## Purpose
How a Locksmith backend service starts, applies its schema, reports health and emits telemetry, so operators and agents can run and debug every service the same way.

## Requirements

### Requirement: Migrations as a separate owner role
Schema migrations SHALL run as a database owner role that the request path never uses. The request path SHALL connect as a role that is neither table owner, superuser nor `BYPASSRLS`. Migrations SHALL be idempotent and SHALL run before the service reports ready.

#### Scenario: Fresh database
- **WHEN** the service starts against an empty database
- **THEN** it applies all migrations as the owner role and then serves requests as the app role

#### Scenario: Restart
- **WHEN** the service restarts against an already-migrated database
- **THEN** it applies nothing and starts normally

#### Scenario: App role cannot bypass isolation
- **WHEN** the app role's attributes are inspected after startup
- **THEN** it is not superuser, not `BYPASSRLS`, and owns no tenant table

### Requirement: Health endpoints
The service SHALL expose `GET /healthz`, which returns `200` while the process runs, and `GET /readyz`, which returns `200` only when the database is reachable and migrations are applied, and `503` otherwise. Neither endpoint SHALL require an org binding or reveal configuration.

#### Scenario: Database down
- **WHEN** Postgres is stopped while the service runs
- **THEN** `/healthz` returns `200` and `/readyz` returns `503` within 5 seconds

### Requirement: Request telemetry
Every HTTP request SHALL produce one OpenTelemetry server span with method, route template and status code, and each database transaction SHALL produce a child span. Traces and logs SHALL be exported over OTLP to the configured endpoint. Spans and logs SHALL carry the org id, but never header values, request bodies or response bodies.

#### Scenario: Trace visible in Grafana
- **WHEN** the e2e suite creates a project and then queries the local Grafana for traces of service `locksmith-api`
- **THEN** a trace with a `POST /v1/projects` server span and a database child span is found

#### Scenario: Telemetry backend down
- **WHEN** the OTLP endpoint is unreachable
- **THEN** requests still succeed, and the export failure is logged at most once a minute
