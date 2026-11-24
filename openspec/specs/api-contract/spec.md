# api-contract Specification

## Purpose

Defines a server-agnostic HTTP scenario suite for the control-plane API, so two implementations can be proven to behave the same.

## Requirements

### Requirement: Every API path has scenarios
The suite SHALL include, for every path and method in `services/control-plane/openapi.json`, a success case, a validation error, a missing-token 401 and a cross-tenant 404 or 403, unless the path is listed as excluded with a reason.

#### Scenario: A path without scenarios fails the suite
- **WHEN** `openapi.json` contains a path and method that has no scenario and is not in the exclusion list
- **THEN** the coverage test fails and names the path

### Requirement: Deterministic, comparable transcripts
The runner SHALL write a normalised transcript in which ids, timestamps and tokens are replaced by stable placeholders, and SHALL report the first differing status, header or body field per path when comparing two servers.

#### Scenario: Two runs against the same server
- **WHEN** the suite runs twice against the Rust control plane
- **THEN** the two normalised transcripts are identical

#### Scenario: Diff of two servers
- **WHEN** `scripts/api-contract.sh --diff` compares two transcripts that differ in one body field
- **THEN** it exits non-zero and prints that path and field
