# ts-tooling Specification

## Purpose

Defines the lint, format and unused-code gates that every TypeScript package passes.

## Requirements

### Requirement: Lint, format and unused-code gates on every TypeScript package
Every TypeScript package SHALL pass oxlint, the oxfmt check, knip and the type check through Turborepo, run by `just lint` locally and in CI.

#### Scenario: Unused export
- **WHEN** a package exports a symbol nothing imports
- **THEN** `just lint` fails and names the file

#### Scenario: Unformatted file
- **WHEN** a TypeScript file differs from oxfmt's output
- **THEN** `just lint` fails and names the file
