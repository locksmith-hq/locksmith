# Proposal: F1 test kit

## Why
The product's one promise is "the secret never reaches the agent side". That promise has to be
checked by a machine on every change, across every place a secret could land:
- DB rows
- logs, traces and metrics labels
- files on disk
- the agent transcript

We also need a fast, uniform way to write Rust and end-to-end tests against the F0 stack.

## Usable outcome
- `just leak-scan`. It plants nothing and only reads. It scans these places for every encoding of the active canaries:
  - Postgres (all text and bytea columns)
  - Loki logs and Tempo span attributes, through the Grafana HTTP API
  - a directory tree
  - a Claude Code transcript file
- It exits non-zero and reports **encoding + location, never the value**.
- `just canary new` mints a canary into `infra/compose/.canaries` (gitignored). Tests use it as a fake secret.
- `cargo nextest` is the test runner. `insta` snapshots, `wiremock` and `testcontainers` are available to every crate. Tests for services run in `tests/e2e`.
- `just test-e2e` runs e2e tests against the F0 stack.

## Out of scope
Product code, adversarial cases for features that do not exist yet (each later change adds its own).

## Depends on
F0.

## Impact
Moves `tests/adversarial/oracle.py` to `tests/kit/oracle.py`. Its `scan` gains Postgres, Loki and Tempo sources.
New: `justfile` recipes, workspace dev-dependencies, `tests/e2e` skeleton, `.config/nextest.toml`.
