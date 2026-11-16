# Tasks

## 1. Detection
- [x] 1.1 `ls_platform::proc::exe_path` (exe path only, no args or environment); `exe_name` uses it.
- [x] 1.2 `ls-broker::source`: agent and host tables, `classify`, ancestor walk, `detect`. Verify: table tests incl. renamed binaries, paths with spaces, control characters, unknown.
- [x] 1.3 Daemon stores source, host and root exe on every lease at start (agent and human). Verify: daemon test asserts the agent lease's source and root exe.

## 2. Self-report
- [x] 2.1 Optional `agent`/`model` on `Request::AgentSessionStart` and `locksmith_start_session`. Verify: old request JSON/CBOR without them parses; MCP schema test still finds no value field.
- [x] 2.2 Validation (64 printable ASCII) with `BadRequest`. Verify: too long, control characters, non-ASCII, empty all refused.
- [x] 2.3 Audit the report in the SESSION_START rule. Verify: daemon test checks the row text.
- [x] 2.4 `locksmith-sessions` skill tells the agent to pass client name and model id.

## 3. Exposure
- [x] 3.1 `LeaseInfo`: `root_exe`, `started_by`, `source`, `host`, `report`, back-compatible. Verify: serialization shape and old-daemon status parse tests; no-secret-material test.
- [x] 3.2 Regenerate `packages/api-types` (`just api-types`).
- [x] 3.3 `smith status` prints source, host and model; `--json` includes the new fields.
- [ ] 3.4 Desktop Sessions tab shows source, host and model (separate change; also update the `LeaseInfo` literal in `apps/desktop/src-tauri/src/tray.rs` tests and `apps/desktop/src/mock.ts`).
