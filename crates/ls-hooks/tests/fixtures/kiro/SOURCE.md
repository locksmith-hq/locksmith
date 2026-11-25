# Kiro fixtures: spike notes (task 1.1)

Read from vendor docs, NOT recorded from a running agent. Checked 2026-11-25 (hooks pages updated
2026-10 and 2026-11; CLI V3 and IDE 1.x). Canary strings only.

## Hooks (https://kiro.dev/docs/hooks/, /hooks/types/, /hooks/actions/)
- Project hooks: `.kiro/hooks/<id>.json`, `{"version":"v1","hooks":[{"name","trigger","matcher","action":{"type":"command","command"},"timeout","enabled"}]}`.
  Global: `~/.kiro/hooks/` (CLI V3). Hooks activate automatically at session start.
- A blocking pre-tool hook EXISTS for a project: trigger `PreToolUse` (IDE, CLI, Web). A command
  action that exits non-zero blocks the tool call; stderr goes to the agent; exit 0 allows
  (actions page). `matcher` is a tool ID, category (`read`, `write`, `shell`, `web`, `spec`), `@mcp`,
  `@<server>`, wildcard, or regex; blank matches every tool.
- Command hooks get JSON on STDIN. The documented event shape is shown for `PermissionRequest`
  and `SubagentStop`: `hook_event_name`, `cwd`, `session_id`, `tool_name`, `tool_input` (object).
  The `PreToolUse` stdin payload is NOT printed on the pages read: assumed to match
  (`tool_name`, `tool_input`): UNVERIFIED.
- `PreToolUse` command hooks may return `hookSpecificOutput.updatedInput` (rewrites input) and
  `permissionDecision` / `permissionDecisionReason` (named on the PermissionRequest page); exit
  code 2 is "deny" there. Exact deny JSON for PreToolUse: UNVERIFIED; exit non-zero is documented.
- Tool IDs seen: `read_file` (input `path`). Others: unverified.

## MCP (https://kiro.dev/docs/mcp/configuration/)
- Workspace `.kiro/settings/mcp.json`, user `~/.kiro/settings/mcp.json`; key `mcpServers`;
  local `{command,args,env,disabled,autoApprove,disabledTools}`; remote `{url,headers,oauth,oauthScopes,...}`.
- Remote OAuth with a pre-registered client: `oauth.clientId` + `oauth.redirectUri` (documented);
  also `oauth.clientMetadataUrl` (CIMD). Web and Mobile ignore the `oauth` block.

## Detection markers
`.kiro/` directory (doc-derived).

## Consequence
A confirmed blocking project hook exists (`PreToolUse`, non-zero exit), but its stdin payload shape
is unverified, so per P3-1 task 2.1 builds the Kiro adapter only from the fields above with the
bounded fail-closed rule (shape mismatch denies), and doctor labels it per P3-2.
