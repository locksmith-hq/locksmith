## ADDED Requirements

### Requirement: History and tree are free of real secrets
The repository SHALL contain no real credential in the tree or in any commit reachable from `main`; every `gitleaks` finding SHALL be either a fake fixture or a revoked value with a written reason.

#### Scenario: Full-history scan is clean
- **WHEN** `gitleaks detect` runs over the full history with `.gitleaksignore`
- **THEN** it reports zero findings, and every ignore entry has a reason comment

#### Scenario: Planted secret fails the check
- **WHEN** a canary credential is added to a scratch copy of the tree
- **THEN** `scripts/public-check.sh` exits non-zero and names the file

### Requirement: Licences are explicit and consistent
Every crate, service, app, package and integration SHALL declare a licence that matches the AGPL-3.0 (server) or Apache-2.0 (SDK, CLI, plugin, schema) split, and a `LICENSE` file for each SHALL exist at the repo root or component root.

#### Scenario: No UNLICENSED component
- **WHEN** `scripts/public-check.sh` runs
- **THEN** it fails if any manifest says `UNLICENSED` or lacks a licence, and passes on the real tree

#### Scenario: AGPL code never enters permissive components
- **WHEN** `cargo deny check licenses` runs
- **THEN** an AGPL dependency of an Apache-2.0 crate fails the check

### Requirement: No owner-only or agent-only material is published
The tree SHALL NOT contain agent app keys, owner contact details beyond the public GitHub handle, private hostnames or cloud account IDs.

#### Scenario: Denylist hit is reported
- **WHEN** a file contains a denylisted pattern
- **THEN** `scripts/public-check.sh` exits non-zero with the file and pattern, and the real tree passes

### Requirement: Public entry docs exist
The repository SHALL have a `README.md` describing the product and quick start, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and `SECURITY.md` with a private reporting path, and their relative links SHALL resolve.

#### Scenario: Broken link fails
- **WHEN** a relative link in a root doc points to a missing file
- **THEN** `scripts/public-check.sh` exits non-zero

### Requirement: The owner has a flip checklist
`docs/going-public.md` SHALL list every owner-only step, in order, with the exact `gh` command or settings path for each.

#### Scenario: Checklist is complete
- **WHEN** the checklist is read against `docs/agents/owner.md` and #307
- **THEN** it covers visibility, re-enabling `ci` and `claude-review`, secret scanning, advisories and rotation of anything flagged
