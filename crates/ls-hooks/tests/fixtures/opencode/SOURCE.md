# OpenCode fixtures: spike notes (task 1.1)

Read from vendor docs, NOT recorded from a running agent. Checked 2026-11-25 (docs site shows
"V2 (latest)" and "V1"; no CLI version is stated on the pages). Canary strings only.

## Two plugin APIs exist (V1 and V2) - they differ
| | V1 (https://opencode.ai/v1/docs/plugins/) | V2 (https://opencode.ai/docs/build/plugins, `/server`) |
|---|---|---|
| Project plugin dir | `.opencode/plugins/` (plural; the P7 design said `.opencode/plugin/`) | `.opencode/plugins/` |
| Entry | `export const X = async (ctx) => ({ ...hooks })` | `export default Plugin.define({ id, async setup(ctx) {...} })` from `@opencode/plugin` |
| Pre-tool hook | `"tool.execute.before": async (input, output)`; `input.tool` is the tool name, `output.args` the arguments | `ctx.tool.hook("execute.before", (event) => ...)`; `event.tool`, `event.input` |
| Deny | throw an `Error` (vendor example "Do not read .env files" for `tool === "read"`, `output.args.filePath`) | unverified (the page shows only logging and input replacement; no throw example read) |
| Project config | `opencode.json` (key `plugin` array for npm packages) | `opencode.json(c)` or `.opencode/opencode.jsonc` (key `plugins`) |
| MCP | `mcp.<name>` (unverified here) | `mcp.servers.<name>` with `type: "local"`, `command: [..]`, `disabled`; "V2 does not place server names directly under `mcp`" |

A single entry can serve both: default-export an object with a V2 `setup()` and a V1 `server()`
(https://opencode.ai/docs/build/plugins/server, "Support V1"): V1 calls `server()` and ignores
`setup()`, V2 does the opposite.

## Facts used
- Auto-load: files under `.opencode/plugins/` load at startup (both versions). A `plugins/` dir
  beside a root `opencode.json` is NOT discovered (V2).
- V2 lets a repo disable plugins with `-<id>` in `plugins`; two built-in policy plugins ignore it.
  A repo-level plugin can therefore be switched off by config: the protection label must say so.
- Remote MCP (V2): OAuth by default, "Pre-registered clients" section exists (https://opencode.ai/docs/mcp-servers/);
  exact keys NOT read: unverified.
- Detection markers: `opencode.json`, `opencode.jsonc`, `.opencode/` (doc-derived).

## Unverified (no hook is built on these, decision P3-1)
- V2 deny mechanism of `execute.before`; tool names beyond `read` and `bash`; argument keys other
  than `filePath` (read) and `command` (bash); the V1 `mcp.<name>` entry shape; OAuth client-id keys.
