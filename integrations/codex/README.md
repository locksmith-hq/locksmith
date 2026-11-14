# Codex

`config.toml` is the hook snippet (generated from `crates/smith-cli/src/agents.rs`; `smith init`
merges it into `.codex/config.toml`). Codex hooks (https://learn.chatgpt.com/docs/hooks, checked
2026-11-14) are on by default, but project hooks load only from a trusted `.codex/` layer and must
be reviewed once with `/hooks`.

What is covered: `Bash` commands (secret reads, env dumps) and `UserPromptSubmit`.

Gaps, stated honestly:
- Codex has no Read tool and `apply_patch` carries a patch, not a path, so file reads outside
  shell commands are not judged.
- `permissionDecision: "ask"` is unsupported and fails open, so ambiguous commands (`eval`,
  base64 into `sh`) are denied with a message to run them manually.
- A hook crash or timeout can let the tool run; only a missing `smith` is made visible and
  blocking by the wrapper (exit 2).
