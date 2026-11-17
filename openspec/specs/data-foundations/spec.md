# data-foundations Specification

## Purpose
TBD - created by archiving change a0-data-and-cloud-foundations. Update Purpose after archive.

## Requirements

### Requirement: Tenant isolation by row-level security
Every tenant-owned table SHALL have an `org_id` column, `FORCE ROW LEVEL SECURITY`, and a policy that restricts rows to `current_setting('app.org_id')`. The application role SHALL be neither the table owner nor `BYPASSRLS`.

#### Scenario: Cross-tenant read returns nothing
- **WHEN** the app role sets org A in a transaction and selects org B's rows
- **THEN** zero rows are returned

#### Scenario: Cross-tenant insert fails
- **WHEN** the app role sets org A and inserts a row with org B's `org_id`
- **THEN** the insert fails with an RLS violation

#### Scenario: Tenant context does not leak across pooled connections
- **WHEN** a transaction sets org A with `set_config(..., true)` and commits, and the same pooled connection is reused without setting an org
- **THEN** queries on tenant tables return zero rows

### Requirement: Time-ordered UUID primary keys
Primary keys SHALL be UUIDv7, generated with `uuidv7()` or by the application.

#### Scenario: IDs sort by creation time
- **WHEN** two rows are inserted one after another
- **THEN** the second ID sorts after the first

### Requirement: Versioned, bound ciphertext format
Every stored ciphertext SHALL start with a header giving format version, algorithm id and key id, and SHALL authenticate the AAD `org_id ‖ secret_id ‖ version ‖ purpose`.

#### Scenario: Round trip
- **WHEN** a value is sealed and opened with the same key and AAD
- **THEN** the plaintext matches

#### Scenario: Moved ciphertext is rejected
- **WHEN** a ciphertext sealed for secret X is opened as secret Y or for another org
- **THEN** opening fails, and the error names the failing check without revealing plaintext

#### Scenario: Unknown version or algorithm is rejected
- **WHEN** the header carries an unknown format version or algorithm id
- **THEN** opening fails with `UnsupportedFormat`
