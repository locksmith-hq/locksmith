# Cline fixtures

Derived from the documented hook schema and source, NOT recorded from a running agent. Sources:
https://raw.githubusercontent.com/cline/cline/main/.clinerules/hooks/README.md and
`apps/vscode/src/sdk/hooks-adapter.ts` (v4.1.27), checked 2026-11-21 (issue #580). The `command`
and `path` parameter keys are assumed (likely, not seen in source); `sdk-run-commands-deny` covers
the SDK/CLI runner shape. Replace with recordings when an agent is available. Canary strings only.

`search_files` keys are an allowlist (`path`, `regex`, `file_pattern`); any other key cancels
(`search-wrong-path-key`, `search-wrong-glob-key`).
