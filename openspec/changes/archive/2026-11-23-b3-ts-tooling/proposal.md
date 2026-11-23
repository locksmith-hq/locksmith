# Proposal: B3 TypeScript tooling (oxlint, oxfmt, knip)

## Why

Owner decision OC-8 (2026-11-22) puts all TypeScript in the repo on oxlint, oxfmt and knip through Turborepo. This was task group 3 of `b1-nestjs-api`, a 44-task change on the critical path held by one worker; it touches no API code, so it is split out (PM 2026-11-23, #653) for another worker to do in parallel. Spike 1.2 of B1 already measured the baseline and the config each package needs (`docs/research/nestjs-typescript7.md`).

## What Changes

- Root oxlint config and a `lint` Turborepo task in every TypeScript package; the ESLint config package is removed once every package passes.
- Root oxfmt config (pinned exactly, pre-1.0), a `format:check` task and one formatting-only commit listed in `.git-blame-ignore-revs`.
- `knip.json` for the workspaces with a `knip` task; every finding fixed or justified.
- `just lint` runs them, so CI (which calls the same just recipes) enforces them without a workflow edit.

**Usable outcome:** a PR that adds an unused export, an unformatted file or a lint error in any TypeScript package fails `just lint` locally and in CI, and names the file.

Out of scope: `apps/api` itself (B1 adds it and inherits the root config); workflow files (trust root; if CI needs a workflow change, it goes on the `harness-backlog` issue); type-check settings beyond the shared tsconfig.

Depends on: none.

## Capabilities

### New Capabilities
- `ts-tooling`: the lint, format and unused-code gates for every TypeScript package.

### Modified Capabilities

## Impact

- Code: root `.oxlintrc.json`, oxfmt config, `knip.json`, `turbo.json`, each package's `package.json` scripts, `justfile`, `.git-blame-ignore-revs`; removal of `packages/eslint-config` at the end.
- The formatting commit touches most TypeScript files: open PRs that edit TypeScript merge main once after it lands.
