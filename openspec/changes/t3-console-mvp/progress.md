# Progress: T3 web console MVP (append-only)

- 2026-11-20 · planning only: proposal, spec, design and tasks written by a worker; no code. `x-depends_on` empty because t1-human-auth is archived on main. Task 5.4 is an owner gate (layout approval), placed last.
- 2026-11-20 · plan revised after review: desktop surface added as group 5, so the owner gate is now task 6.4 (not 5.4).
- 2026-11-20 · worker: group 1 done on claude/change-t3-console-mvp. Client gained org, project, environment, secret-metadata and version-list methods (no value or material method); vitest added to control-plane-client; 401 wrapper and in-memory fixtures in apps/web/src/api. msw not added (design.md updated). Groups 2-7 remain.
