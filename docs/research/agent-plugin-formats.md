# Agent plugin formats: Gemini CLI, Copilot, Windsurf, Cline

Research for OpenSpec change `p3-agent-plugins`, task 1.1. Captured 2026-11-20.

Method: WebFetch of primary docs where the session network allowed it, and WebSearch result
summaries otherwise. The session could not resolve `code.visualstudio.com`, `docs.github.com`,
`docs.windsurf.com` or `docs.cline.bot`, so for those the facts come only from search-result
summaries of those pages (secondary: marked **search-only**). Anything not seen in either is
marked **UNVERIFIED** and must be checked against the vendor docs before a recorded fixture
(task 2.1) is trusted. Nothing here was run against a real agent.

Verification levels: **verified** (read in the primary doc by fetch), **search-only**,
**UNVERIFIED** (from prior knowledge, or the doc could not be read).

## Summary

| Agent | Blocking pre-tool hook | Project hook file | Project MCP file | Repo markers used |
|---|---|---|---|---|
| Gemini CLI | yes (`BeforeTool`, `BeforeAgent`), verified | `.gemini/settings.json` | `.gemini/settings.json` (`mcpServers`) | `.gemini/`, `GEMINI.md` |
| Copilot (VS Code, CLI, cloud agent) | yes (`preToolUse`), search-only | `.github/hooks/*.json` | VS Code `.vscode/mcp.json` (UNVERIFIED); CLI `.mcp.json` or `.github/mcp.json` (verified) | `.github/copilot-instructions.md`, `.github/hooks/` (UNVERIFIED) |
| Windsurf | yes (`pre_*` hooks, exit 2), search-only | workspace `hooks.json` path UNVERIFIED | user-level only (UNVERIFIED) | `.windsurf/`, `.windsurfrules` (UNVERIFIED) |
| Cline | yes (`PreToolUse` script), search-only | `.clinerules/hooks/` | user-level only (UNVERIFIED) | `.clinerules/`, `.cline/` (UNVERIFIED) |

## Gemini CLI

Sources (fetched 2026-11-20):
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/hooks/index.md
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/hooks/reference.md
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/mcp-server.md

Config (verified). `settings.json`, layers merged with highest precedence first: project
`.gemini/settings.json`, user `~/.gemini/settings.json`, system `/etc/gemini-cli/settings.json`,
extensions. Hooks and MCP servers live in the same file.

Hook events (verified): `SessionStart`, `SessionEnd`, `BeforeAgent`, `AfterAgent`,
`BeforeModel`, `AfterModel`, `BeforeToolSelection`, `BeforeTool`, `AfterTool`, `PreCompress`,
`Notification`. Locksmith uses `BeforeTool` and `BeforeAgent`.

Hook config (verified):

```json
{"hooks": {"BeforeTool": [{"matcher": "regex on tool name",
  "hooks": [{"name": "x", "type": "command", "command": "...", "timeout": 5000}]}]}}
```

`type` is only `command`; `timeout` is milliseconds (default 60000). The matcher is a regex
for `BeforeTool`. Whether an omitted matcher matches every tool is **UNVERIFIED** (the generator
omits it on that assumption: if wrong, the hook would not fire, so check this first).

Payload on stdin (verified):
- `BeforeTool`: `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `timestamp`,
  `tool_name`, `tool_input` (object), optional `mcp_context`, `original_request_name`.
- `BeforeAgent`: base fields plus `prompt`.
- Exact tool names and `tool_input` keys (shell command, file path) are **UNVERIFIED**; they need
  a recorded fixture.

Reply (verified): exit 0 and stdout JSON, `{"decision":"deny","reason":"..."}` (`block` is an
alias; `reason` required on deny). Exit 2 blocks the tool with stderr as the reason (BeforeTool)
or aborts the turn (BeforeAgent). Other exit codes are a non-fatal warning and the action
PROCEEDS. Non-JSON stdout defaults to Allow. So the fail-closed wrapper must use exit 2.

MCP (verified): top-level `mcpServers`; stdio entry `{"command", "args", "env", "cwd",
"timeout", "trust", "includeTools", "excludeTools"}`. Stdio servers show as Disconnected unless
the folder is trusted. Do not set `trust`.

Detection: `.gemini/` directory (the project settings location, verified). `GEMINI.md` as a
context file marker is **UNVERIFIED**.

## GitHub Copilot

Sources:
- Search result summary of https://docs.github.com/en/copilot/reference/hooks-reference and
  https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference
  (search-only, 2026-11-20; the pages could not be fetched).
- https://code.visualstudio.com/docs/copilot/customization/hooks (VS Code hooks, Preview;
  appeared in search, could not be fetched).
- https://raw.githubusercontent.com/github/docs/main/content/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers.md
  (fetched 2026-11-20, verified, Copilot CLI MCP).
- https://raw.githubusercontent.com/github/copilot-cli/main/README.md (fetched; no hook or MCP
  path info).

Hooks (search-only): files are loaded from `.github/hooks/*.json`, JSON `version` 1. A
`preToolUse` hook controls execution by writing exactly one JSON object to stdout:
`permissionDecision` is `allow`, `deny` or `ask`; `permissionDecisionReason` is required on
deny; empty output means default behaviour; two or more JSON objects concatenate into invalid
JSON and are ignored. A command `preToolUse` error denies the tool call, but a timeout falls
through to normal permissions. In cloud agent jobs only the `bash` field of a command hook is
honoured, `powershell` is ignored.

UNVERIFIED (not seen in any fetched text): the exact entry keys (the generator uses
`{"type":"command","bash":...,"timeoutSec":10}`), the stdin payload field names (tool name and
arguments), the exit-code semantics (the generator assumes exit 2 with stderr is treated as an
error and so denies), and whether VS Code agent mode reads the same `.github/hooks/*.json` file
with the same casing (VS Code hooks are documented as Preview and may use PascalCase events).
Event names other than `preToolUse` (for example a prompt-submit hook) are UNVERIFIED, so the
generator wires only `preToolUse`.

MCP:
- Copilot CLI (verified): user file `~/.copilot/mcp-config.json`; project `.mcp.json` or
  `.github/mcp.json` (searched from the working directory up to the repo root, `.mcp.json` wins,
  project servers load only after folder trust). Schema: top-level `mcpServers`, entry
  `{"type":"local","command","args","env","tools"}` (`tools: ["*"]` default). `.vscode/mcp.json`
  is NOT read by the CLI.
- VS Code agent mode: `.vscode/mcp.json` with top-level `servers` and entry
  `{"type":"stdio","command","args"}` is **UNVERIFIED** (page not fetchable; prior knowledge).
  The generator writes this file. The CLI needs its own `mcpServers` file, so one MCP file does
  NOT serve both: design decision 4 (one directory) holds, but two MCP files are needed.

Detection: `.github/copilot-instructions.md` and `.github/hooks/` are **UNVERIFIED** markers.
The CLI binary is `copilot` (UNVERIFIED).

## Windsurf (Cascade)

Sources (search-result summaries only, 2026-11-20; pages could not be fetched):
- https://docs.windsurf.com/windsurf/cascade/hooks
- https://docs.devin.ai/desktop/cascade/hooks

Hooks (search-only): pre-hooks `pre_user_prompt`, `pre_read_code`, `pre_write_code`,
`pre_run_command`, `pre_mcp_tool_use` can block by exiting with code 2; post-hooks cannot.
System-level `hooks.json` lives at `/Library/Application Support/Windsurf/hooks.json` (macOS)
and `C:\ProgramData\Windsurf\hooks.json` (Windows); user-level and workspace-level files are also
loaded and merged. Hooks do not run in Restricted Mode.

UNVERIFIED: the workspace path (the generator assumes `.windsurf/hooks.json`), the user path,
the JSON schema (the generator assumes `{"hooks":{"<event>":[{"command":"...","show_output":false}]}}`),
the stdin payload (event name plus a `tool_info` object with the command or file path), whether
`command` runs through a shell (the wrapper uses `command -v ... ||` shell syntax), and whether
stderr is shown to the agent on exit 2.

MCP: user-level `~/.codeium/windsurf/mcp_config.json` with `mcpServers` is **UNVERIFIED**. No
repo-level MCP file is known, so `smith init` prints the manual step instead of writing it.

Detection: `.windsurf/` and `.windsurfrules` are **UNVERIFIED**.

## Cline

Sources (search-result summaries only, 2026-11-20; pages could not be fetched):
- https://docs.cline.bot/customization/hooks.md
- https://docs.cline.bot/features/hooks/samples
- https://cline.bot/blog/cline-v3-36-hooks

Hooks (search-only): `PreToolUse` runs before Cline executes a tool (such as `read_file`,
`write_to_file`). Project hooks live in `.clinerules/hooks/` and can be committed. Hooks read
JSON on stdin and write JSON to stdout; `{"cancel": false}` allows and
`{"cancel": true, "errorMessage": "..."}` blocks; `contextModification` can feed text back. The
sample filters on `.preToolUse.toolName`. The docs list global hooks at `~/Documents/Cline/Hooks/`
while the launch post says `~/Documents/Cline/Rules/Hooks/` (a discrepancy). The launch post said
hooks were macOS and Linux only; may be outdated.

UNVERIFIED: that a hook is an executable file named exactly `PreToolUse` with no extension (the
generator assumes this and marks it executable), the full stdin shape (the generator does not
parse it yet), exit-code semantics (the wrapper always replies on stdout and exits 0, so it does
not depend on them), and Windows support.

MCP: Cline keeps servers in `cline_mcp_settings.json` (a user-level file under the extension's
global storage). That it is user-level only, and its schema (`command`, `args`, `env`,
`disabled`, `alwaysAllow`), are **UNVERIFIED**. `smith init` prints the manual step.

Detection: `.clinerules/` (directory) and `.cline/` are **UNVERIFIED** markers.

## Verification pass, 2026-11-21 (Ada, issue #580)

Source: https://github.com/locksmith-hq/locksmith/issues/580 (comment 7069109339). Ada has open
internet; her answer resolves the UNVERIFIED items above except those listed under "Still open".
This section supersedes the per-agent text above where they differ. WebFetch output is a model
summary, so quotes are near-verbatim. Nothing was run against a real agent.

### Gemini CLI (v0.70.0, 2026-11-19), verified from source and docs
- An omitted matcher matches every tool (`packages/core/src/hooks/hookPlanner.ts` `matchesContext`);
  `""` and `"*"` do too. The generator's no-matcher choice is correct.
- Tool names: shell `run_shell_command` with `{command, is_background, description?}`; `write_file`
  `{file_path, content}`, `replace` `{file_path, old_string, new_string, ...}`, `read_file`
  `{file_path}`, plus `read_many_files`, `glob`, `grep_search`, `list_directory`, `web_fetch`,
  `google_web_search`. MCP tools are `mcp_<server>_<tool>` (single underscores).
- Reply: exit 0 parses stdout JSON (`decision` allow|deny, `block` alias, `reason`); exit 2 blocks
  with stderr as the reason; any other exit code only warns and the tool runs.
- Project hooks run only in a **trusted** folder; a changed project hook is treated as new and
  untrusted. `smith doctor` should warn about this.
- Markers `GEMINI.md` and `.gemini/settings.json` are confirmed.

### GitHub Copilot, verified from vendor docs
- Hook files: CLI reads `.github/hooks/*.json`, `~/.copilot/hooks/*.json`, inline `hooks` in
  `.github/copilot/settings.json`; the cloud agent reads only `.github/hooks/*.json`; VS Code agent
  mode reads `.github/hooks/*.json` (and `.claude/settings.json` with `chat.useClaudeHooks`). One
  `.github/hooks/locksmith.json` serves all three.
- Schema `{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"...","powershell":"...",
  "cwd":"...","env":{},"timeoutSec":30,"matcher":"regex"}]}}`; the generator's entry is valid.
- Payload depends on the event name casing: `preToolUse` gives `{sessionId, timestamp(ms), cwd,
  toolName, toolArgs}` (tools `bash`, `powershell`, `edit`, `create`, `view`, `glob`, `grep`,
  `web_fetch`, `task`, `ask_user`); `PreToolUse` gives `{hook_event_name, session_id, timestamp,
  cwd, tool_name, tool_input}` with Claude-style names. `toolArgs` may be a JSON string or an
  object: parse both.
- Reply `{"permissionDecision":"allow|deny|ask","permissionDecisionReason":"..."}`; reason required
  on deny; cloud agent treats `ask` as deny. Exit 2 denies; any other non-zero exit denies.
  **A timeout fails open**: keep `timeoutSec` generous (default 30); doctor should mention it.
- MCP: VS Code `.vscode/mcp.json` (`servers`, `{type:"stdio",command,args,env}`) is verified but
  deprecated (docs say Feb 2027) for a portable `.mcp.json` with `mcpServers`. CLI: `.mcp.json`
  beats `.github/mcp.json`; user file `~/.copilot/mcp-config.json`; entries `type: local|http`.
- Markers: `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`; binary
  `copilot`, npm `@github/copilot`.
- Sources: docs.github.com/en/copilot/reference/hooks-reference,
  code.visualstudio.com/docs/copilot/customization/hooks,
  code.visualstudio.com/docs/agents/reference/mcp-configuration,
  docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers,
  docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-custom-instructions.

### Windsurf is now Devin Desktop, partly verified
- `docs.windsurf.com` redirects to `docs.devin.ai`. Current hooks file: `.devin/hooks.v1.json`
  (project or user), Claude-style `PreToolUse` with `matcher` and `type: "command"`. Hooks do not
  load in Restricted Mode (https://docs.devin.ai/desktop/cascade/hooks).
- The linked CLI hooks page (https://docs.devin.ai/cli/extensibility/hooks/overview.md; not
  confirmed to apply to Desktop): omitted or empty matcher matches all; payload `{hook_event_name,
  tool_name, tool_input, session_id, prompt_id}`; shell tool `exec` with `tool_input.command`;
  reply `{"decision":"block","reason":...}`; exit 2 blocks; any other exit, a timeout or unreadable
  output **fails open**.
- Legacy Windsurf (third-party and search results only, medium-low confidence): workspace
  `.windsurf/hooks.json`, user `~/.codeium/windsurf/hooks.json`; schema
  `{"hooks":{"<event>":[{"command":"...","show_output":bool}]}}`; payload `agent_action_name` and
  `tool_info.{command_line,file_path}`; pre-hooks block on exit 2.
- MCP (https://docs.devin.ai/desktop/cascade/mcp): project `.devin/mcp_config.json`, local
  `.devin/mcp_config.local.json`, user `~/.config/devin/mcp_config.json`. Schema not shown.
- Markers: `.devin/rules/` plus legacy `.windsurf/rules/*.md`, `.windsurf/global_rules.md`,
  `.windsurfrules`; `AGENTS.md` is read. Add `.devin/` as a marker.
- **Decision:** treat Windsurf as Devin Desktop; detect `.devin/` and `.windsurf/`; until a fixture
  confirms `.devin/hooks.v1.json`, `smith doctor` reports Windsurf as "unknown, not protected".

### Cline (v4.1.27, 2026-11-21), verified from source and docs
- Hook file: executable named exactly after the event, no extension, with a shebang:
  `.clinerules/hooks/PreToolUse` (https://raw.githubusercontent.com/cline/cline/main/.clinerules/hooks/README.md).
  Hook dirs: `.cline/hooks/` (new), `.clinerules/hooks/` (legacy, still read), `~/.cline/hooks/`,
  `~/Documents/Cline/Hooks/`, `CLINE_HOOKS_DIR` (the launch post's `Rules/Hooks` path is stale).
- Hooks are not supported on Windows in the VS Code extension, and need "Enable Hooks" on.
- Payload `{clineVersion, hookName, timestamp, taskId, workspaceRoots, userId,
  preToolUse:{toolName, parameters}}`. `parameters` values are **strings** (`toStringRecord`).
  Shell tool `execute_command`; file tools use `path`. The SDK/CLI runner uses another shape
  (`tool_call:{id,name,input}`, shell tool `run_commands`): parse both.
- Reply `{"cancel":bool,"contextModification":"...","errorMessage":"..."}`; `cancel` required;
  timeout 30 s (extension) or 120 s (CLI). Exit-code semantics undocumented: always exit 0 with JSON.
- MCP: `cline_mcp_settings.json`, user-level only; CLI path `~/.cline/data/settings/cline_mcp_settings.json`
  or `CLINE_MCP_SETTINGS_PATH`; keys `mcpServers.{command,args,env,disabled,autoApprove,type,url,headers}`
  (https://docs.cline.bot/mcp/configuring-mcp-servers).
- Markers `.clinerules/` and `.cline/` are confirmed.

### Still open
- Command key inside Copilot's `toolArgs` (likely `command`).
- Cline exit codes and the `command` parameter key (likely `command`).
- Legacy Windsurf shell behaviour and stderr handling; Devin Desktop's hook and MCP schemas.
- No real agent was run: task 2.1 fixtures derived from these docs must be marked as such in
  `SOURCE.md` and replaced by recordings when an agent is available.

## Library check

No maintained cross-agent hook or config merge library was found in this research; the formats
are small, so the in-house merge in `crates/smith-cli/src/agents.rs` stays.

## Follow-ups before relying on this

1. Allow `docs.github.com`, `code.visualstudio.com`, `docs.windsurf.com`, `docs.cline.bot` in
   the session network and re-run the UNVERIFIED items.
2. Record one real payload per hook event (task 2.1) from an installed agent, with the capture
   date in `SOURCE.md`.
3. `smith doctor` must report agent versions it has not seen as unknown, not protected.
