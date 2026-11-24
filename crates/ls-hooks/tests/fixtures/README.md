# Hook adapter golden fixtures

`<agent>/<case>.in.json` is the agent's hook stdin; `.out.json` is `{code, stdout, stderr?}` as
produced by `ls_hooks::adapters::handle` against `NoVault`. `__CWD__` is replaced by a temp dir
holding `.env`, `__KEY__` by a runtime-built fake key. Regenerate with `UPDATE_GOLDEN=1 cargo test
-p ls-hooks --test golden`, then review the diff.

Schemas checked on 2026-11-14:

- Claude Code: https://code.claude.com/docs/en/hooks. `PreToolUse` input `tool_name`, `tool_input`
  (`Bash.command`, `Read/Edit.file_path`, `Grep.path/glob`, `Glob.path/pattern`); output
  `hookSpecificOutput.permissionDecision` deny|ask (allow is deliberately never sent: it would
  skip the user's own permission prompts, so Allow is empty output). `UserPromptSubmit` input
  `prompt`; block is `{"decision":"block","reason"}` plus `suppressOriginalPrompt` so the secret
  is not echoed. Exit 2 blocks, other non-zero codes do not. MultiEdit's schema was not in the
  docs excerpt read; `file_path` is assumed.
- Cursor: https://cursor.com/docs/agent/hooks. Output keys are snake_case (`user_message`,
  `agent_message`), not camelCase. `beforeReadFile` supports only allow|deny; `beforeSubmitPrompt`
  answers `{continue, user_message}`. Exit 2 blocks, other codes fail open unless `failClosed`.
- Codex: https://learn.chatgpt.com/docs/hooks (redirect from developers.openai.com/codex/hooks).
  Hooks exist (`hooks.json` or `[[hooks.PreToolUse]]` in `config.toml`, on by default, project
  hooks need a trusted `.codex/` and `/hooks` review). Shell is `Bash`; there is no Read tool.
  `ask` is unsupported and fails open, so Ask becomes deny.
- Gemini CLI, Copilot, Cline: derived from vendor docs on 2026-11-21, not recorded; see each
  directory's `SOURCE.md` and `docs/research/agent-plugin-formats.md`. Gemini blocks with exit 2
  and stderr; Copilot answers `permissionDecision` JSON (exit 2 on malformed input); Cline answers
  `{cancel, errorMessage}` on exit 0 and cancels on malformed input.
