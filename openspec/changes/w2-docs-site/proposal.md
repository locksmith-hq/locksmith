# Proposal: W2 Docs Site (parallel track)

## Why

Beta testers and agents both need precise docs. Agents especially read docs to learn the supported
path after a block. Docs that live next to the code, with the CLI reference generated from it,
stay correct.

## What Changes

- `apps/docs`: Astro Starlight using `packages/ui` tokens, deployed to `docs.<domain>`.
- Sections: Quickstart (5 minutes to a protected agent session), Concepts (vault, sessions,
  delegation modes and their guarantee labels), Guides per agent (Claude Code, Cursor, Codex, Grok
  Build, OpenHands, Gemini CLI), per credential type (Git, HTTP APIs, DBs, AWS), Team admin,
  Troubleshooting (generated from doctor check ids), Reference.
- Generated reference: CLI (from clap via `clap-markdown`), `.locksmith.toml` and policy schema (from
  `schemars`), doctor checks (id, meaning, remediation, from the registry), telemetry schema, MCP
  tools.
- `llms.txt` and `llms-full.txt` for agents, and every block message links to a stable docs anchor.
- Versioned docs per minor release, with search (Pagefind).

## Usable outcome

Every milestone's features are documented on the day they ship. An agent that hits a block can follow
a link to the exact supported alternative.

## Capabilities

### New Capabilities
- `public-docs`: Public documentation content, generated references and agent-readable docs.

### Modified Capabilities

## Out of scope

- Translations.

## Impact

`apps/docs`. A small `xtask` crate in `crates/` emits the reference JSON and markdown at build time.
Starts after M0, and each milestone adds its pages as part of its own tasks.
