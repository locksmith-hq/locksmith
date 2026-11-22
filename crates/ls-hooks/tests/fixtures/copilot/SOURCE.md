# GitHub Copilot fixtures

Derived from the documented hook schema, NOT recorded from a running agent. Source:
https://docs.github.com/en/copilot/reference/hooks-reference and
https://code.visualstudio.com/docs/copilot/customization/hooks, checked 2026-11-21 (issue #580).
`toolArgs` is documented as "unknown"; the `command` and `path` keys inside it are assumed and
must be confirmed by a recording. Fixtures cover `toolArgs` as a JSON string and as an object, and
the Claude-style `PreToolUse` casing. Canary strings only.

Version: none. No Copilot CLI or VS Code was run, so there is no agent version to cite; the docs
pages above (checked 2026-11-21) are the only source. Owner accepted doc-derived fixtures on #594
on the condition that an unrecognised key denies: `grep-missing-path` and the other
`*-missing-*` fixtures cover it.
