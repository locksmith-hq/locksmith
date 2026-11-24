@AGENTS.md

# Claude Code notes

## Subagent model tiers
- **Sonnet** (`model: sonnet`): the default for all work, including feature code on secret paths, CLI, doctor checks, integration tests, CI fixes and refactors.
- **Opus** (`model: opus`): only hard, complex work: new crypto or protocol design, subtle security reasoning, cross-cutting design, merge reviews, and tasks Sonnet already failed.
- **Haiku** (`model: haiku`): the fast execution engineer, for clearly defined isolated tasks, search, running tests, and repetitive edits.

When unsure, use Sonnet and escalate only if it fails evaluation. Split a mixed task so each part runs on the right tier.

## Agent harness
The scheduled agents' prompts, skills and scripts live in `locksmith-hq/claude-ai-crew`; owner rules, lessons and
routing live in `locksmith-hq/locksmith-roadmap`. Only `.claude/skills/merge-review` stays here: `claude-review.yml`
runs it as the merge review.

## OpenSpec
- `openspec list` shows the changes.
- `/opsx:apply <id>` implements a change.
- `/opsx:archive <id>` archives one.

## GitHub
Write `@claude` in any PR or issue comment to get Claude to help through GitHub Actions. PRs with auto-merge enabled get an automatic Opus merge review (the required `merge-ready` check; see `.github/workflows/claude-review.yml`).
