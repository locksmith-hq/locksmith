# Tasks: H1 test recipes

## 1. Recipe table and check [sonnet]
- [ ] 1.1 Write `docs/testing.md`: a row per component directory (path, kind, test command, needs `just up`, covered by, notes), found by listing `crates/*`, `services/*`, `apps/*`, `packages/*`, `integrations/*`, `tests/e2e`, `tests/adversarial` and `tests/kit`; run each listed command once and record the result in progress.md.
- [ ] 1.2 Add the "Dev environment" section to `docs/testing.md`, linking `docs/dev-harness.md` and `docs/cloud-dev.md` and naming the existing `just` recipes for the local stack; link `docs/testing.md` from `docs/dev-harness.md`, `services/README.md` and `integrations/README.md`.
- [ ] 1.3 Add `scripts/test-recipes-check.sh` (missing row, stale row, `just` recipe named in the dev section that does not exist) with a test script `scripts/test-recipes-check.test.sh` that plants each failure in a temp copy; call the check from `scripts/tree-check.sh`.
- [ ] 1.4 Verify: `bash scripts/test-recipes-check.test.sh` and `just tree-check` pass, and `just tree-check` fails with a planted `crates/ls-planted/Cargo.toml`.

## 2. `just test <name>` [sonnet]
- [ ] 2.1 Add the `test name` recipe to the `justfile`: Rust dirs via `cargo metadata` to `cargo nextest run -p <package>`, npm dirs with a `test` script to `npm test --workspace <dir>`, npm dirs without one (`apps/web`) to their covered-by row (`just test-web`), `apps/desktop` to `just desktop-test`, `tests/e2e`, `tests/adversarial` and `tests/kit` to their runners, covered rows to their covering component, and an unknown name to a non-zero exit listing valid names.
- [ ] 2.2 Verify: `just test control-plane`, `just test web`, `just test ls-vault` and `just test desktop` pass; `just test no-such-thing` exits non-zero; record the outputs in progress.md.

## 3. Local verification [sonnet]
- [ ] 3.1 Run `just up`, `just test control-plane` (the smoke test of this change), `just apps-build`, then `just ci`.
