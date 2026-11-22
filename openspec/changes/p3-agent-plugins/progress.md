
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

## 2026-11-21 worker (harriet, second run)
- Task: 3.1-3.4 - done; evaluator PASS (independent sonnet)
- Verified: `cargo nextest run -p smith-cli init doctor` 31 passed; `cargo test -p smith-cli --test init` 11 passed; `just quick` OK
- Notes for next session: Gemini trust file format (`~/.gemini/trustedFolders.json`) and Copilot timeout fail-open are doc/memory-derived, unconfirmed. Windsurf stays gated (config_path still `.windsurf/hooks.json`, real format `.devin/hooks.v1.json`). Next: task 4 (generate integrations/gemini-cli, copilot). 2.1 still open. Also checked d2/d3: only UI tasks blocked on t3 bindings page.

## 2026-11-21 23:59 worker (harriet, third run)
- Task: 4.1-4.5 - done; merged origin/main (4 conflicts in smith-cli: hub MCP kept alongside new-agent wiring, mcp_path is Option); evaluator PASS (independent sonnet)
- Verified: `cargo test -p smith-cli` all pass; `UPDATE_INTEGRATIONS=1 cargo test -p smith-cli --bin smith agents`; `just test gemini-cli` and `just test copilot` 166 passed; locksmith-mcp --test integrations passed; `just quick` OK
- Notes for next session: next is task 5 (windsurf, cline; windsurf still gated by hook_handler_ready) then 6 and 7. No live-CLI variant exists: the smoke test only prints "skip live" when the CLI is absent. 2.1 still open (doc-derived fixtures). d2-aws-sts and d3-db-relay remain parked on the t3 bindings page (#489).

## 2026-11-22 worker (harriet)
- Task: 5.1-5.4 - done (windsurf generated but labelled "unknown, not protected": no hook handler until a Devin Desktop fixture exists; cline script generated, executable, replayed against recorded fixtures); merged origin/main (clean)
- Verified: `UPDATE_INTEGRATIONS=1 cargo test -p smith-cli --bin smith agents`; `cargo test -p smith-cli --test integrations` 5 passed; `just test windsurf` and `just test cline`
- Notes for next session: next is task 6 (generic-mcp) then 7; 2.1 still open (doc-derived fixtures). d2-aws-sts and d3-db-relay remain parked on the t3 bindings page (#489).

## 2026-11-22 worker (alfie)
- Task: 6.1-6.3 - done (generated `integrations/generic-mcp/mcp.json` via the drift test; README gets the stdio section with the lost protections; handshake test covers the snippet; testing.md row)
- Verified: `UPDATE_INTEGRATIONS=1 cargo test -p smith-cli --bin smith agents` 14 passed; `cargo test -p locksmith-mcp --test integrations` passed; `just quick`/`just test generic-mcp` below
- Notes for next session: next is task 7 (install table in docs, leak scan) then 8; 2.1 still open (doc-derived fixtures).

## 2026-11-22 worker (alfie, second entry)
- Task: 7.1 - done (supported-agents install table with protection labels in `integrations/README.md`)
- Verified: `bash scripts/tree-check.sh` OK; `gitleaks detect --no-git` over `integrations/` and `crates/ls-hooks/tests/fixtures` no leaks
- Notes for next session: 7.2/7.3 left open: `just leak-scan` fails on this VM (`bad canary file`, no stack canaries), so run it where the canary file exists or via CI. 2.1 and 8.x still open.

## 2026-11-22 worker (harriet)
- Task: 7.2-7.3 - done (`just up`, `just canary new`, then `just leak-scan --dir integrations --dir crates/ls-hooks/tests/fixtures --dir crates/smith-cli/tests/fixtures` clean; tree-check OK)
- Verified: leak-scan "clean"; `bash scripts/tree-check.sh` OK
- Notes for next session: 2.1 (recorded fixtures) and 8.1/8.2 still open; main CI `rust` failed once on 16bc9ed but `just test-rust` passes locally (963 passed), likely a flake; stack is up on this VM only.

## 2026-11-22 worker (harriet, second entry)
- Task: 8.1 - done (`just test` for gemini-cli, copilot, windsurf, cline, generic-mcp all rc=0; `smith init --yes` and `smith doctor` in a scratch repo with all markers: gemini and copilot hooks ok, windsurf warns "not protected" as designed)
- Verified: as above; `just quick` OK
- Notes for next session: open: 2.1 (recorded fixtures, doc-derived only) and 8.2 (`just apps-build`, CI). Do not run `just ci` locally; the PR checks run it.

## 2026-11-22 worker (alfie, third entry)
- Task: 8.2 - NOT ticked (evaluator FAIL: CI was green on e815c95, not on the merged head; `just apps-build` rc=0 after `npm ci`; PR checks on e815c95 all green: hygiene, rust, web, desktop, macos, windows-check, adversarial)
- Verified: as above; merged origin/main (clean)
- Notes for next session: tick 8.2 once CI is green on the pushed head (apps-build already passed locally). Then only 2.1 is open (recorded payloads from real Gemini/Copilot/Cline sessions; no agent CLI on the VM, fixtures stay doc-derived). It needs an owner decision to accept doc-derived fixtures or a session with the CLIs; do not enable auto-merge until then. d2-aws-sts and d3-db-relay remain parked on the t3 bindings page (#489).

## 2026-11-22 worker (alfie, third entry)
- Task: none ticked; 8.2 not ticked (independent evaluator FAIL: CI was green on e815c95, not on the merged head)
- Verified: `npm ci` then `just apps-build` rc=0 locally; PR checks on e815c95 all green
- Notes for next session: tick 8.2 once CI is green on this pushed head (apps-build already passed). Then only 2.1 is open (recorded payloads from real Gemini/Copilot/Cline; no agent CLI on the VM, fixtures stay doc-derived), which needs a session with those CLIs or an owner decision. Do not enable auto-merge until then. d2-aws-sts and d3-db-relay remain parked on the t3 bindings page (#489).

## 2026-11-22 worker (alfie, fourth entry)
- Task: 8.2 - done (PR checks all green on head 5513ed8: hygiene, rust, web, desktop, macos, windows-check, adversarial; `just apps-build` rc=0 locally)
- Verified: check-runs on 5513ed8; `just quick` below
- Notes for next session: only 2.1 is open (recorded payloads need real Gemini/Copilot/Cline CLIs; fixtures stay doc-derived). Opened a `Decision:` needs-rescue so the lead can accept doc-derived fixtures or split 2.1 out. Do not enable auto-merge until then.

## 2026-11-22 lead (rescue #594)
- Task: 2.1 - NOT ticked (rescue-attempt; two Opus evaluations FAIL)
- Decision: accept doc-derived fixtures (design.md row 7, decisions.md P3-2) on condition that a wrong assumed key fails closed.
- Fix (d50ab8d): `unreadable()` in gemini_cli/copilot/cline denies a known tool whose input does not parse; `*-missing-path` fixtures. `cargo nextest run -p ls-hooks` 16/16, `-p smith-cli --test hook` 9/9, `just quick` OK.
- Still failing: search tools (`grep_search`, `grep`, `search_files`) parse with path and glob both optional, so wrong keys allow (evaluator reproduced with `target/debug/smith`: gemini `grep_search` with `path:<dir>/.env` exit 0). Also: copilot SOURCE.md lacks a version; fixture path differs from task text (ls-hooks convention).
- Next: deny (or ask) a known search tool whose args yield neither path nor glob, add `*-search-missing-*` fixtures, re-evaluate; then tick 2.1. Escalated on #594.
