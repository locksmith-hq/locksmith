# NestJS 12 on TypeScript 7: spike result (change b1-nestjs-api, task 1.1)

Run 2026-11-22 in a throwaway project outside the repo (Node 24.21, npm 11.19, public npm registry, `--ignore-scripts`).

## Question

NestJS 12's official migration guide pins `typescript@^6`. TypeScript 7 is the current release (the native compiler). Nest depends on decorators and `emitDecoratorMetadata`. Does the stack build, run and test on TypeScript 7.0.2?

## Result: yes, on TypeScript 7.0.2

A small app: controller, service injected through the constructor (needs emitted `design:paramtypes`), a zod 4 validation of the query, `@nestjs/platform-express`, ESM (`"type": "module"`, `module: nodenext`).

| Check | TypeScript 7.0.2 | TypeScript 6.0.3 |
|---|---|---|
| `tsc` build (5 files) | 0.49 s | 1.01 s |
| Decorator metadata emitted (`design:paramtypes` in the controller) | yes | yes (same config) |
| App runs, `GET /hello?name=world` | `{"message":"hello world"}` | `{"message":"hello six"}` |
| Invalid query | 400 with the zod issue list | not repeated |
| Needs `"types": ["node"]` in tsconfig | yes (default `types` is empty) | yes |

Tests: vitest 5.1.1 (Vite 8.3.8, rolldown) running `Test.createTestingModule` plus supertest passed in 0.5 s. **No swc plugin was needed**: the same test passed with and without `unplugin-swc`, so DI resolves under vitest's own transform. (My first assumption, that a plugin was required, was wrong, so the plan needs one dependency less.)

Tooling on the same project:
- oxlint 1.94.0: clean, decorators parse.
- oxfmt 0.79.0 (`--check`): clean; it warns that no config exists and uses defaults.
- knip 6.47.0: reports `dist/` as unused files and `oxlint`/`oxfmt` as unused devDependencies, so it needs a config (`entry: src/main.ts`, `ignore: dist`) and package scripts that call the tools. No decorator problems.

## Not tested (verify in the real app)

`@nestjs/cli` (`nest build` and `nest start --watch`), `@nestjs/swagger` with zod, `nestjs-cls`, `nestjs-pino`, Kysely, pg-boss, project references or incremental builds on a large codebase, and type-aware oxlint (needs a separate tool). The app was five files.

## Recommendation for gate G3

Pin `typescript` to exactly `7.0.2`. TypeScript 6.0.3 is proven too and is the fallback if a later task finds a break. Put `"types": ["node"]` in the shared tsconfig base. Do not add `unplugin-swc` unless a real test proves it necessary.

## Sources

- npm registry data, read 2026-11-22: @nestjs/core 12.6.0 (MIT, `"type": "module"`, engines node >= 20, released 2026-11-20), typescript 7.0.2 (Apache-2.0, 2026-07-08), 6.0.3, vitest 5.1.1, oxlint 1.94.0, oxfmt 0.79.0, knip 6.47.0 (registry.npmjs.org).
- NestJS migration guide: https://docs.nestjs.com/migration-guide (pins TypeScript 6).
- NestJS 12 deep dive (ESM, Standard Schema): https://dev.to/x4nent/nestjs-12-deep-dive-full-esm-migration-standard-schema-route-validation-and-the-4fe0

## Task 1.2: oxlint, oxfmt and knip over the real packages

Run 2026-11-22 on `main` (74393b38) over `apps/web/src`, `apps/desktop/src`, `packages/{ui,control-plane-client,sdk,api-types}/src`, with oxlint 1.94.0, oxfmt 0.79.0 and knip 6.47.0 from the public registry, default configuration.

| Tool | Result | Config it needs |
|---|---|---|
| oxlint | 0 errors, 14 warnings: 10 `no-unused-vars` (nine are `_` parameters in `apps/desktop/src/screens.tsx` and one `init` in `auth.test.tsx`), 2 `no-unsafe-optional-chaining` (`control-plane-client/src/mcp.test.ts`), 2 `no-control-regex` (`apps/web/src/mockup/pages/securityStore.ts`, probably intended) | `.oxlintrc.json` with `no-unused-vars` ignoring names that start with `_` (then fix the `init` one), the two test files reviewed, and an inline disable with a reason for the regex |
| oxfmt | 86 of 98 files would change under defaults (25,522 insertions and 8,969 deletions). A wider `printWidth` barely helps (120: 86 files, 160: 84, 200: 83) because the code is hand-formatted with dense one-liners | A `.oxfmtrc.json`; accept one repo-wide formatting-only commit listed in `.git-blame-ignore-revs` (task 3.2), generated `schema.d.ts` and the CSS files excluded |
| knip | 26 unused files, 1 unused devDependency (`openapi-typescript` in `control-plane-client`), 1 unlisted dependency (`react` imported by `packages/ui/src/kit.tsx`), 2 unlisted binaries (`tsc` in `control-plane-client` and `sdk`), 2 unused exports (`agent` in `desktop/src/screens.tsx`, `createFixtures` in `web/src/api/fixtures.ts`), 2 unused types (`AgentsClient`, `SignedInUser`) | `knip.json` with workspaces: `apps/web` entries including `src/mockup/main.tsx` (24 of the 26 unused files are the mockup entry's tree) and `tests/e2e/sdk-smoke/smoke.test.ts` as a test entry; list `react` as a peer dependency of `packages/ui` and `typescript` as a devDependency where `tsc` is called |

Reading the numbers: oxlint and knip are cheap to adopt (a config and about a dozen small fixes). oxfmt is the expensive one: it rewrites nearly every file, so it should land as its own commit with nothing else in it, after the other tooling PRs, and the formatting diff is not a review item. Until then `format:check` stays out of CI (task 3.4 adds it after 3.2).
