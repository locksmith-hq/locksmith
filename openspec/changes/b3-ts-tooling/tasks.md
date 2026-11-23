# Tasks: B3 TypeScript tooling

## 1. Lint [haiku]
- [ ] 1.1 Root oxlint config (exact version pinned, settings from `docs/research/nestjs-typescript7.md`) and a `lint` Turborepo task in every TypeScript package (`apps/web`, `apps/desktop`, `apps/docs`, `packages/*`).
- [ ] 1.2 Fix or justify each oxlint finding (baseline 14 warnings); remove `packages/eslint-config` only when every package passes, and list any leftovers in progress.md.
- [ ] 1.3 Verify: `npx turbo run lint` is green.

## 2. Format [haiku]
- [ ] 2.1 Root oxfmt config with an exact pinned version and a `format:check` Turborepo task per package.
- [ ] 2.2 One formatting-only commit over every TypeScript package; add its sha to `.git-blame-ignore-revs`.
- [ ] 2.3 Verify: `npx turbo run format:check` is green.

## 3. Unused code [sonnet]
- [ ] 3.1 `knip.json` (workspaces, entry files per app including the console mockup entry, every ignore with a reason) and a `knip` Turborepo task.
- [ ] 3.2 Fix or justify every knip finding (baseline 26 unused files and a few dependency fixes).
- [ ] 3.3 Verify: `npx turbo run knip` is green.

## 4. Enforce [haiku]
- [ ] 4.1 `just lint` runs `turbo run lint format:check knip typecheck`, and `just quick` covers changed TypeScript files; no workflow edit (CI calls `just lint`); if CI still misses a check, note it on the `harness-backlog` issue.
- [ ] 4.2 `docs/testing.md` lists the TypeScript gates and how to run one package's checks.
- [ ] 4.3 Verify: plant an unused export in a scratch commit, `just lint` fails naming the file; remove it, `just lint` and `just quick` pass.

## 5. Local verification
- [ ] 5.1 `just up`, `npx turbo run lint format:check knip typecheck`, `just apps-build`, then `just quick`.
