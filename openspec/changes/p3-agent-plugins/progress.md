
## 2026-11-20 worker (C)
- Task: 1.2-1.4 - done; 1.1 left open (research doc written but most vendor facts UNVERIFIED: VS Code, docs.github.com, windsurf and cline docs hosts were unreachable from the VM)
- Verified: `cargo test -p smith-cli --bin smith agents` 11 passed; `just ci` -> exit 0; Sonnet evaluator found one blocker (init would wire hooks for agents `smith hook` cannot handle yet), fixed by gating via `agents::hook_handler_ready` (remove it in task 2.2).
- Notes for next session: re-verify the UNVERIFIED items in docs/research/agent-plugin-formats.md (esp. Gemini `matcher` omitted - possible silent fail-open) and then tick 1.1; task 2 next. `mcp_path` is now Option (Windsurf/Cline have none).

## 2026-11-21 worker (harriet)
- Task: none - blocked (task 1.1 / 2.1 need verified vendor formats; this VM cannot reach the vendor docs)
- Verified: merged origin/main clean, tree clean; opened needs-research #580 with one question covering every UNVERIFIED item
- Notes for next session: when #580 is answered, update `docs/research/agent-plugin-formats.md`, tick 1.1, then do task 2 (fixtures first). Also checked d2-aws-sts and d3-db-relay: only the t3-console-mvp bindings page (#489, review-failed, another worker's) blocks their remaining tasks.

## 2026-11-21 worker (harriet, woken by research answer on #580)
- Task: 1.1, 2.2, 2.3, 2.4 - done; 2.1 left open (fixtures are doc-derived, not recorded)
- Verified: `cargo nextest run -p ls-hooks -p smith-cli hook` -> all pass; golden 59 cases; `just quick` OK; Sonnet evaluator PASS, its fail-open finding (missing command key) fixed
- Notes for next session: fixtures live in `crates/ls-hooks/tests/fixtures/{gemini-cli,copilot,cline}` with SOURCE.md (doc-derived; Copilot `toolArgs.command` and Cline `parameters.command` keys unconfirmed). Windsurf is Devin Desktop (`.devin/hooks.v1.json`): no adapter yet, still gated by `hook_handler_ready`; 2.1 can only close when recordings exist or the owner accepts doc-derived fixtures. Next: task 3 (init/doctor; add doctor warnings for Gemini untrusted folders, Copilot timeout fail-open, Windsurf unknown/not protected; add `.devin/` marker).
