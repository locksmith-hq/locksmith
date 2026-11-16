@AGENTS.md

# Claude Code notes

## Subagent model tiers
- **Opus** (`model: opus`): secrets, crypto, the vault, authorization and audit paths, relays, adversarial gates, protocol work, and cross-cutting design or merge reviews.
- **Sonnet** (`model: sonnet`): feature code outside the secret paths, CLI, doctor checks, integration tests, CI fixes and refactors. This is the default tier.
- **Haiku** (`model: haiku`): the fast execution engineer, for clearly defined isolated tasks, search, running tests, and repetitive edits.

When unsure, go one tier up. Split a mixed task so each part runs on the right tier.

## Skills
Repeatable procedures live as skills in `.claude/skills/`, each with scripts. Use the skill instead of improvising:
- `run-start`
- `long-commands`
- `evaluate-escalate`
- `run-log`
- `merge-queue`
- `merge-review` (runs in GitHub Actions)
- `archive-change`

## OpenSpec
- `openspec list` shows the changes.
- `/opsx:apply <id>` implements a change.
- `/opsx:archive <id>` archives one, or use the `archive-change` skill.

## GitHub
Write `@claude` in any PR or issue comment to get Claude to help through GitHub Actions. PRs labelled `ready-to-merge` get an automatic Opus merge review.
