# GitHub Copilot fixtures

Derived from the documented hook schema, NOT recorded from a running agent. Source:
https://docs.github.com/en/copilot/reference/hooks-reference and
https://code.visualstudio.com/docs/copilot/customization/hooks, checked 2026-11-21 (issue #580).
`toolArgs` is documented as "unknown"; the `command` and `path` keys inside it are assumed and
must be confirmed by a recording. Fixtures cover `toolArgs` as a JSON string and as an object, and
the Claude-style `PreToolUse` casing. Canary strings only.
