---
name: design-system-mcp
description: Set up, run and use the Locksmith design system MCP server, which answers what components exist, their props, examples and colour tokens. Use before building or changing any web UI in this repo, when an agent needs a component's API, or when the design-system MCP server is missing or fails to start.
---

# Locksmith design system MCP

This is an internal tool for building Locksmith. It is not published and is not for users of the product. The server lives in `design-system/mcp/` and runs over stdio. It reads the design system's source in this checkout (`design-system/packages`, the docs site's demos, `tokens.css`, the README), so its answers always match the tree you are on. It only reads; it changes nothing.

## Configure

**In this repository it is already configured.** `.mcp.json` at the repo root has:

```json
"design-system": { "command": "node", "args": ["design-system/mcp/server.mjs"] }
```

Two things must be true before it starts:

1. Dependencies are installed. Run `npm ci` at the repo root once per checkout or worktree.
2. The client has approved the project's MCP servers. Claude Code asks the first time; answer yes, or run `claude mcp list` to see its state.

**From another client on your machine** (Claude Desktop, Cursor, Codex), point at the file in your checkout by absolute path:

```json
{
  "mcpServers": {
    "locksmith-design-system": {
      "command": "node",
      "args": ["/absolute/path/to/locksmith/design-system/mcp/server.mjs"]
    }
  }
}
```

With Claude Code: `claude mcp add locksmith-design-system -- node /absolute/path/to/locksmith/design-system/mcp/server.mjs`.

It needs Node 24 (the repo's `.nvmrc`) and no environment variables, tokens or network.

## Run and check it

A client starts the server itself. To check it by hand:

```bash
npm test --workspace @locksmith-hq/design-system-mcp     # its own tests
npx @modelcontextprotocol/inspector node design-system/mcp/server.mjs   # browse the tools in a browser
```

`node design-system/mcp/server.mjs` on its own prints nothing and waits: that is correct, it is waiting for a client on stdin.

## Tools

| Tool | Use it to |
|---|---|
| `list_components` | Find the component for a job. Call it first. |
| `get_component` | Get one component's install and import lines, exported parts, variants, props and a working example. Takes `name`: `"button"`, `"data-table"`, `"DataTable"`. |
| `get_tokens` | Get colour tokens with light and dark values. Optional `filter`: `"state"`, `"brand"`, `"chart"`. |
| `get_guide` | Read how to install the kit in an app and how to add or change a component. |

## How to use it when building UI

The repo's UI rules (`AGENTS.md`) say every web UI is built from the kit. So:

1. `list_components`, and pick the component. Do not hand-write a control the kit has.
2. `get_component` for each one you will use, and copy the shape of its example.
3. `get_tokens` for any colour. Use the variable (`var(--brand)`) or its Tailwind class (`bg-brand`), never a hex code.
4. If the kit lacks what you need, stop: adding to `design-system/` is owner-reviewed. Say what is missing.

## When it fails

| Symptom | Cause and fix |
|---|---|
| `Cannot find package '@modelcontextprotocol/sdk'` | Dependencies are not installed in this checkout. Run `npm ci` at the repo root. |
| `props without a description` on stderr, then exit | A component's `<Name>Props` has an undocumented prop. Document it; the docs build fails on the same thing. |
| The client lists no `design-system` server | The project's MCP servers were not approved, or the client was started outside the repo root. |
| `get_component` has `example: null` | The component has no demo in `design-system/docs/src/demos.tsx`. Its props and variants are still correct. |
