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
