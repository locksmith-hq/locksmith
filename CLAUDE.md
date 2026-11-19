@AGENTS.md

# Claude Code notes

## Subagent model tiers
- **Sonnet** (`model: sonnet`): the default for all work, including feature code on secret paths, CLI, doctor checks, integration tests, CI fixes and refactors.
- **Opus** (`model: opus`): only hard, complex work: new crypto or protocol design, subtle security reasoning, cross-cutting design, merge reviews, and tasks Sonnet already failed.
- **Haiku** (`model: haiku`): the fast execution engineer, for clearly defined isolated tasks, search, running tests, and repetitive edits.

When unsure, use Sonnet and escalate only if it fails evaluation. Split a mixed task so each part runs on the right tier.

## Agent-system changes (#470)
Agent-system files (`docs/agents`, `.claude/skills`, agent scripts, workflows; full list in `scripts/check-task-edits.sh`) change only on an `owner/harness-release-<YYYY-WW>` branch or a `*hotfix-*` branch (red main, a security fix, every run failing). In any other session, comment the idea on the `harness-backlog` issue instead.

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
