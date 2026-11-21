
## 2026-11-20 worker (C)
- Task: 1.2-1.4 - done; 1.1 left open (research doc written but most vendor facts UNVERIFIED: VS Code, docs.github.com, windsurf and cline docs hosts were unreachable from the VM)
- Verified: `cargo test -p smith-cli --bin smith agents` 11 passed; `just ci` -> exit 0; Sonnet evaluator found one blocker (init would wire hooks for agents `smith hook` cannot handle yet), fixed by gating via `agents::hook_handler_ready` (remove it in task 2.2).
- Notes for next session: re-verify the UNVERIFIED items in docs/research/agent-plugin-formats.md (esp. Gemini `matcher` omitted - possible silent fail-open) and then tick 1.1; task 2 next. `mcp_path` is now Option (Windsurf/Cline have none).
