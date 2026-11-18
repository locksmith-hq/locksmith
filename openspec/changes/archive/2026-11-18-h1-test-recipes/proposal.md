# H1 test recipes for every component

## Why
The end goal requires that every piece of the code has a recipe for how to test it, plus recipes for running the local stack and connecting to the dev environment. Today the recipes exist only in aggregate: `just test-rust` runs the whole workspace, `just test-web` runs every npm workspace, and `cargo test -p <crate>` works only if you know that `services/control-plane` is the package `ls-control-plane`. None of the 30 component directories under `crates/`, `services/`, `apps/`, `packages/` and `integrations/` documents how to test it (only `integrations/codex` has a README at all), and nothing stops a new crate from landing with no recipe. Agents and new contributors guess, which costs tokens and produces wrong verification commands in tasks.

## What Changes
- **`docs/testing.md`:** one table with a row per component (path, kind, test command, needs `just up`, notes), plus a short "Dev environment" section that points to the existing recipes (`just up`, `just down`, `just logs`, `just psql`, `just mcp-check`, `just harness-check`, `docs/dev-harness.md`, `docs/cloud-dev.md`) instead of repeating them.
- **`just test <name>`:** runs one component's tests by directory name (`just test control-plane`, `just test web`, `just test ls-vault`). It resolves Rust directories to their Cargo package with `cargo metadata`, npm directories to their workspace, `apps/desktop` to `just desktop-test`, and `tests/e2e`, `tests/adversarial` and `tests/kit` to their existing runners. A component with no tests of its own names the component that covers it, and `just test` runs that one.
- **Coverage check:** `scripts/test-recipes-check.sh`, run by `just tree-check`, fails when a component directory has no row in `docs/testing.md`, or a row names a directory that no longer exists.
- **Links:** `AGENTS.md` is protected, so `docs/testing.md` is linked from `docs/dev-harness.md` and the `integrations/README.md` / `services/README.md` indexes instead.

## Capabilities
### New Capabilities
- `test-recipes`: every component has a documented, runnable test recipe, and the repository enforces it.

### Modified Capabilities
None.

## Usable outcome
An agent or contributor who touches any directory can run `just test <dir-name>` and get that component's tests, or read one table to find the command and whether it needs the local stack. A new crate without a recipe fails `just ci`.

## Out of scope
- Writing new tests for components that have none (the table says which component covers them; real tests come with the change that grows them, for example P3 for the integrations).
- CI workflow changes (CI stays lint and hygiene only; `tree-check` already runs there).
- Per-component README files.
- Coverage measurement.

## Depends on
none
