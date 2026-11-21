# Progress: p4-sdks

## 2026-11-20 pm (planning)
- Task: planned the change (proposal, spec, design, tasks) because workers were idle (#536).
- Verified: `openspec validate p4-sdks`, `bash scripts/change-status.sh`, `bash scripts/tree-check.sh`.
- Notes for next session: group 4 edits `agents.rs` after p3-agent-plugins; merge main first.
- 2026-11-21 · worker (alfie): group 1 done: `packages/sdk` with openapi-fetch 0.17.0 (re-checked, MIT), `createLocksmith`, `LocksmithError`, `paginate`, drift, coverage and no-value-route tests (8 pass). Stacked on claude/change-m1-remote-mcp. Next: group 2 (control-plane-client on the SDK).
- 2026-11-21 · worker (alfie): group 2 done: control-plane-client now runs on @locksmith/sdk (own fetch code, schema.d.ts and gen:types removed; ApiError extends LocksmithError; relative base URL kept via placeholder origin; enrollment-secret test added). Verified: control-plane-client 9, web 26, desktop 28 tests, tsc, npm run build (tauri build not run). Next: group 3 (just sdk-gen/sdk-smoke, README).
- 2026-11-21 · worker (alfie): 2.3 left unticked: the `tauri build` half of `just apps-build` was not run in this VM.
