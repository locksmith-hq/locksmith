# Progress: p4-sdks

## 2026-11-20 pm (planning)
- Task: planned the change (proposal, spec, design, tasks) because workers were idle (#536).
- Verified: `openspec validate p4-sdks`, `bash scripts/change-status.sh`, `bash scripts/tree-check.sh`.
- Notes for next session: group 4 edits `agents.rs` after p3-agent-plugins; merge main first.
- 2026-11-21 · worker (alfie): group 1 done: `packages/sdk` with openapi-fetch 0.17.0 (re-checked, MIT), `createLocksmith`, `LocksmithError`, `paginate`, drift, coverage and no-value-route tests (8 pass). Stacked on claude/change-m1-remote-mcp. Next: group 2 (control-plane-client on the SDK).
- 2026-11-21 · worker (alfie): group 2 done: control-plane-client now runs on @locksmith/sdk (own fetch code, schema.d.ts and gen:types removed; ApiError extends LocksmithError; relative base URL kept via placeholder origin; enrollment-secret test added). Verified: control-plane-client 9, web 26, desktop 28 tests, tsc, npm run build (tauri build not run). Next: group 3 (just sdk-gen/sdk-smoke, README).
- 2026-11-21 · worker (alfie): 2.3 left unticked: the `tauri build` half of `just apps-build` was not run in this VM.

## 2026-11-21 09:25 UTC worker
- Task: ci-fix (hygiene red on PR #554) - ci-fix
- Verified: scripts/public-check.sh -> OK; vitest control-plane-client -> 9 passed; just quick -> OK
- Notes for next session: gitleaks flagged the enrollment-secret test fixture (generic-api-key); now built from low-entropy words. 12 tasks still unticked, so no auto-merge yet.
- 2026-11-21 · worker (alfie): groups 1 and 2 re-landed on `claude/change-p4-sdks-v2`: PR #554 was stacked on the already-merged m1 branch, so its commits never reached main and were reverted there (fa0c5ca). This branch reverts that revert from main. Verified: sdk 8, control-plane-client 9 tests, tree-check. Next: group 3.
- 2026-11-21 · worker (alfie): group 3 done: `just sdk-gen`, `just sdk-smoke` (signs in as the seeded user, create/list/delete an agent through the SDK, then `leak-scan` clean; verified against `just up` + `just api`), `packages/sdk/README.md`; the `docs/testing.md` row already existed. Verified: `just test sdk` 8 pass, `just tree-check`. Next: group 4 after p3-agent-plugins lands `agents.rs`.

## 2026-11-21 12:20 UTC worker
- Task: 3.1-3.4 - done
- Verified: `just sdk-smoke` (live stack) -> pass, leak-scan clean; `just test sdk` -> 8 pass; `just quick` -> OK
- Notes for next session: 2.3 still unticked (tauri build not run in this VM). Group 4 edits agents.rs: wait for p3-agent-plugins. Stop-hook asked for noreply@anthropic.com authorship; ignored because the persona commits as locksmith-alfie[bot].

## 2026-11-21 16:15 UTC worker
- Task: ci-fix (PR #561 merge conflicts) - done
- Verified: sdk 8 and control-plane-client 9 vitest -> pass; just quick -> OK
- Notes for next session: merged origin/main (vitest ^4.1.12 and openapi-typescript kept, @locksmith/sdk dependency kept; sdk vitest bumped to ^4.1.12). Group 4 can start now: agents.rs is on main. 4.1 needs open internet (mark "not verified" or open needs-research). 2.3 still needs the tauri build.

## 2026-11-21 worker (alfie)
- Task: group 4 (4.1-4.5) - done
- Verified: `cargo nextest run -p smith-cli init doctor agents` 30 pass; `just test smith-cli` 136 pass; `just quick` OK; drift test regenerated `integrations/claude-code/.mcp.hub.json`, `integrations/codex/config.hub.toml`.
- Notes: Claude Code and Codex verified from sources (remote-mcp-auth.md section 6); Cursor stays unsupported (docs host unreachable). Left: 2.3 (tauri build not run in this VM), 5.1 (just up + sdk-smoke + apps-build + ci; `just ci` is banned locally, PR checks run it), 5.2 (manual ci-platforms, last of phase only). Not finishing the PR: tasks remain.
