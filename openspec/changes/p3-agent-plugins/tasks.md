# Tasks: P3 agent plugins

## 1. Formats and generator [sonnet]
- [x] 1.1 [haiku] Research spike: for Gemini CLI, Copilot (VS Code agent mode and CLI), Windsurf and Cline record in `docs/research/agent-plugin-formats.md` (with source URLs and date) the project and user config paths, MCP server schema, whether a blocking pre-tool or pre-prompt hook exists, its payload and reply shape, and the repo markers for detection.
- [x] 1.2 Add the four `Agent` variants to `agents.rs` (id, events, binaries, detect, `config_path`, `mcp_path`), extending `ALL`; agents without a hook get an empty events list and a `protection()` label (prevention, detection or none).
- [x] 1.3 Extend `wrapper`, `json_entry`, `hooks_json`, `merge_hooks` and `merge_mcp` for the new formats, fail-closed in each agent's denial shape; unit tests for idempotence, preserving other settings and invalid input, as for the existing agents.
- [x] 1.4 Verify: `cargo test -p smith-cli --bin smith agents`.

## 2. Hook handling [sonnet]
- [ ] 2.1 Capture one recorded payload fixture per hook event for each hooked new agent under `crates/smith-cli/tests/fixtures/hooks/<agent>/` (source and capture date in a sibling `SOURCE.md`; no secret values, canary strings only).
- [x] 2.2 `hook_cmd.rs`: parse each new agent's payload and answer in its reply shape using the existing `ls_hooks` decision; unknown or unparsable payload denies; update the unknown-agent error text.
- [x] 2.3 Tests replaying the fixtures: secret read denied, env dump denied, benign command allowed, malformed payload denied, denial audited.
- [x] 2.4 Verify: `cargo nextest run -p smith-cli hook`.

## 3. Init and doctor [sonnet]
- [x] 3.1 `smith init`: detect, merge hooks and MCP for the new agents; print the manual step where a config lives outside the repo.
- [x] 3.2 `smith doctor`: per-agent check for the new agents including the protection label and a clear line for hookless agents.
- [x] 3.3 Tests: second `smith init` changes nothing, invalid config untouched, doctor output for hooked and hookless agents.
- [x] 3.4 Verify: `cargo nextest run -p smith-cli init doctor`.

## 4. Gemini CLI and Copilot integrations [sonnet]
- [x] 4.1 Generate `integrations/gemini-cli` files and add them to `integrations_match_generated`; hand-write its README (install, what is blocked, protection label).
- [x] 4.2 Same for `integrations/copilot` (VS Code agent mode and CLI).
- [x] 4.3 [haiku] Smoke test per integration: replay recorded hook fixtures and the `locksmith-mcp` stdio handshake (`initialize`, `tools/list`); run the live variant only if the agent CLI is on `PATH`, otherwise print `skip live` for that variant only.
- [x] 4.4 [haiku] Add `docs/testing.md` rows for `integrations/gemini-cli` and `integrations/copilot`.
- [x] 4.5 Verify: `UPDATE_INTEGRATIONS=1 cargo test -p smith-cli --bin smith agents` then `just test gemini-cli && just test copilot`.

## 5. Windsurf and Cline integrations [sonnet]
- [x] 5.1 Generate `integrations/windsurf` files and extend the drift test; README with the protection label.
- [x] 5.2 Same for `integrations/cline`.
- [x] 5.3 [haiku] Smoke tests as in 4.3 for both, and `docs/testing.md` rows.
- [x] 5.4 Verify: `UPDATE_INTEGRATIONS=1 cargo test -p smith-cli --bin smith agents` then `just test windsurf && just test cline`.

## 6. Generic MCP setup [haiku]
- [x] 6.1 `integrations/generic-mcp/README.md` and a generated `mcp.json` snippet (stdio `locksmith-mcp`, no secrets), noting that no hook protection applies and which protections are lost.
- [x] 6.2 Smoke test (snippet parses, handshake succeeds) and `docs/testing.md` row.
- [x] 6.3 Verify: `just test generic-mcp`.

## 7. Docs and leak safety [haiku]
- [x] 7.1 Update `integrations/README.md` (generated file list, regenerate command) and add an install table to the docs for all supported agents with their protection labels.
- [x] 7.2 Run the leak scan over new fixtures and integration files; fix any hit.
- [x] 7.3 Verify: `just leak-scan` and `bash scripts/tree-check.sh`.

## 8. Local verification [sonnet]
- [x] 8.1 `just up`, then `just test <name>` for gemini-cli, copilot, windsurf, cline and generic-mcp and a `smith init` plus `smith doctor` run in a scratch repo carrying all agent markers.
- [x] 8.2 `just apps-build`, then `just ci`.
