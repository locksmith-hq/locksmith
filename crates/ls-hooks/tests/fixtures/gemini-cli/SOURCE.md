# Gemini CLI fixtures

Derived from the documented hook schema, NOT recorded from a running agent (none was available).
Source: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/hooks/reference.md and
`packages/core/src/tools/definitions/base-declarations.ts` (v0.70.0), checked 2026-11-21 by the
research routine (issue #580). Replace with recordings when an agent is installed. Canary strings
only (`__KEY__` is built at test time).

Search keys are an allowlist (decision P3-2, #594): `grep_search` reads `dir_path` and
`include_pattern` (plus `pattern`, `exclude_pattern` and bool/number options); `read_many_files`
reads `include` (plus `exclude`, `recursive`, `useDefaultExcludes`, `file_filtering_options`) and
checks every entry. Any other key, such as `path` or `include`, denies (`search-wrong-*-key`,
`read-many-wrong-key`).
