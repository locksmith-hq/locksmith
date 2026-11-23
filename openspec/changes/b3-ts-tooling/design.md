# Design: B3 TypeScript tooling

## Context

Split out of `b1-nestjs-api` (its design decision 8). Baseline from B1 spike 1.2 (`docs/research/nestjs-typescript7.md`): oxlint 14 warnings and 0 errors, oxfmt would change 86 of 98 files, knip finds 26 unused files (mostly the console mockup entry) and a few dependency fixes.

## Decisions and evidence

| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | oxlint, oxfmt and knip through Turborepo | ESLint and Prettier | Owner decision OC-8; B1 design decision 8 |
| 2 | oxfmt pinned to an exact version; formatting diffs are not review blockers | Caret range | oxfmt is pre-1.0 (B1 design) |
| 3 | One formatting-only commit, listed in `.git-blame-ignore-revs` | Format file by file | Keeps `git blame` useful |
| 4 | CI enforcement through `just lint`, not a workflow edit | Edit `.github/workflows` | Workflows are trust root; CI jobs already call the just recipes (AGENTS.md "CI policy") |

## OSS used

| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| oxlint | MIT | 1.94.0 | 2026-11-16 | Lint | not AGPL |
| oxfmt | MIT | 0.79.0 | 2026-11-16 | Format | not AGPL |
| knip | ISC | 6.47.0 | 2026-11-20 | Unused files, exports, dependencies | not AGPL |

Versions from B1's design (checked 2026-11-22); the task that adds each package confirms the current version.

Built in-house: nothing.

## How an agent debugs this

- Commands: `npx turbo run lint format:check knip --filter=<pkg>`, `npx knip --workspace <pkg>`, `just lint`, `just quick`.
- No services, tables or traces are involved.

## Risks

- The formatting commit conflicts with open TypeScript PRs; land it in one commit early, and those PRs merge main once.
