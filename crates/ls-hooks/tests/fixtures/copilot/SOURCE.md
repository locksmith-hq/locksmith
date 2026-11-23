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

Search keys are an allowlist: `grep` (and Claude-style `Grep`) reads `path` and `glob` plus
`pattern`, ripgrep-style options and bool/number values; any other key denies
(`grep-wrong-path-key`, `pascal-grep-wrong-key`). The `PreToolUse` casing fails closed the same
way as `preToolUse` (`pascal-*-wrong-key`, `pascal-read-no-input`) and also reads Copilot's own
lowercase tool names (`pascal-view-env-deny`).

Bounded P3-2 rule (design.md row 7): a tool event whose name or input is not under the expected
keys denies (`*-shape-mismatch-*`), and every string in a known tool's input except its content
keys is checked against the protected-path policy (`*-decoy-key-*`).
