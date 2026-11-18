# test-recipes Specification

## Purpose
TBD - created by archiving change h1-test-recipes. Update Purpose after archive.

## Requirements

### Requirement: Every component has a documented test recipe
The repository SHALL list every component directory (each direct child of `crates/`, `services/`, `apps/`, `packages/` and `integrations/`, plus `tests/e2e`, `tests/adversarial` and `tests/kit`) in `docs/testing.md` with its test command, whether it needs `just up`, and, when it has no tests of its own, the component that covers it.

#### Scenario: A new crate without a recipe fails the check
- **WHEN** a directory `crates/ls-planted` with a `Cargo.toml` exists and `docs/testing.md` has no row for it
- **THEN** `bash scripts/test-recipes-check.sh` exits non-zero and names `crates/ls-planted`
- **AND** `just tree-check` fails

#### Scenario: A row for a removed directory fails the check
- **WHEN** `docs/testing.md` has a row for a directory that does not exist
- **THEN** `bash scripts/test-recipes-check.sh` exits non-zero and names that row

#### Scenario: The current tree passes
- **WHEN** the check runs on main after this change
- **THEN** it exits 0

### Requirement: One command runs one component's tests
The repository SHALL provide `just test <name>`, where `<name>` is a component directory name, that runs that component's tests and exits with their status.

#### Scenario: A service directory maps to its Cargo package
- **WHEN** a developer runs `just test control-plane`
- **THEN** it runs `cargo nextest run -p ls-control-plane` and exits with its status

#### Scenario: An npm workspace with a test script runs it
- **WHEN** a developer runs `just test <name>` for an npm workspace that has a `test` script
- **THEN** it runs `npm test --workspace <dir>` and exits with its status

#### Scenario: A workspace without tests names its covering recipe
- **WHEN** a developer runs `just test web`, and `apps/web` has no `test` script and no tests
- **THEN** its row says it is covered by `just test-web` (build plus the root `npm test`, which skips workspaces without a `test` script), and the recipe prints that and runs it

#### Scenario: A component covered elsewhere runs the covering tests
- **WHEN** a developer runs `just test` on a component whose row names a covering component
- **THEN** it prints which component covers it and runs that component's tests

#### Scenario: An unknown name fails clearly
- **WHEN** a developer runs `just test no-such-thing`
- **THEN** it exits non-zero and prints the list of valid names

### Requirement: Dev environment recipes are indexed
`docs/testing.md` SHALL have a "Dev environment" section that names the existing recipes for starting, stopping, inspecting and connecting to the local stack and the cloud dev setup, each as a link or a `just` recipe that exists in the `justfile`.

#### Scenario: Every named recipe exists
- **WHEN** `bash scripts/test-recipes-check.sh` runs
- **THEN** every `just <recipe>` named in the "Dev environment" section is a recipe in `just --summary`, or the check fails naming it
