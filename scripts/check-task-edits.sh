#!/usr/bin/env bash
# Guard: on implementation branches (claude/change-*, change/*) an agent may only tick or untick
# OpenSpec tasks, never edit, add or remove task text. Planning branches may edit freely.
# Why: Anthropic's long-running-agent harness found models rewrite Markdown task lists to look done
# (https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents).
# Usage: BRANCH=<name> scripts/check-task-edits.sh   (BRANCH defaults to the current git branch)
set -euo pipefail

branch="${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"

# Agents (claude/* branches) may never change their own rules, CI, or this guard.
# Exception: claude/learning-* may edit skills (not merge-queue), role files and helper scripts;
# gates, workflows, AGENTS.md/CLAUDE.md, config and .claude settings stay owner-only for everyone.
protected_fail=0
if [[ "$branch" == claude/* ]] && git rev-parse -q --verify origin/main >/dev/null; then
  paths=(.github/workflows 'scripts/check-task-edits*' scripts/merge-gate.sh scripts/check-agent-docs.sh
         AGENTS.md CLAUDE.md openspec/config.yaml .claude/settings.json .claude/settings.local.json .claude/agents
         .claude/skills/merge-queue .claude/skills/merge-review docs/agents/merge.md docs/agents/common.md scripts/run-lock.sh scripts/worker-has-work.sh scripts/change-status.sh scripts/change-issue.sh scripts/change-sync.sh scripts/roadmap-sync.sh scripts/issue-lib.sh scripts/dates-sync.sh)
  # Learning branches may improve other skills, role files, lessons and helper scripts.
  [[ "$branch" == claude/learning-* ]] || paths+=(docs/agents .claude/skills scripts/run-meta.sh scripts/agent-start.sh scripts/agent-preflight.sh scripts/bg.sh)
  # owner.md and openspec/decisions.md: agents may only append (new owner decisions), never edit existing lines.
  ob=$(git merge-base HEAD origin/main)
  for f in docs/agents/owner.md openspec/decisions.md; do
    if git cat-file -e "$ob:$f" 2>/dev/null; then
      old=$(git show "$ob:$f" | wc -c)
      { [ -f "$f" ] && cmp -s -n "$old" <(git show "$ob:$f") "$f"; } || { echo "task-edit guard: $f is append-only for agents"; protected_fail=1; }
    fi
  done
  changed=$(git diff --name-only "$(git merge-base HEAD origin/main)" -- "${paths[@]}" | grep -v '^docs/agents/owner.md$' || true)
  if [ -n "$changed" ]; then
    echo "task-edit guard: agent branch '$branch' changed protected files (owner-only):"; echo "$changed"
    protected_fail=1
  fi
fi

case "$branch" in
  claude/change-*|change/*) ;;
  *) echo "task-edit guard: task checks skipped on branch '$branch'"; exit "$protected_fail" ;;
esac

base_ref=origin/main
if ! git rev-parse -q --verify "$base_ref" >/dev/null; then
  echo "task-edit guard: $base_ref not found (fetch it); skipping" >&2; exit 0
fi
base=$(git merge-base HEAD "$base_ref")

# Strip the checkbox state so only a tick/untick compares equal.
norm() { sed -E 's/^([[:space:]]*- )\[[ xX]\]/\1[?]/'; }

# Where a change file lives now: in place, or moved by `openspec archive` into archive/<date>-<id>/.
current() { [ -f "$1" ] && { echo "$1"; return; }
  find openspec/changes/archive -path "*-$(basename "$(dirname "$1")")/$(basename "$1")" 2>/dev/null | sort | tail -1; }

fail=$protected_fail
while IFS= read -r f; do
  git cat-file -e "$base:$f" 2>/dev/null || continue   # a new tasks.md (new change or archive copy) is allowed
  cur=$(current "$f")
  if [ -z "$cur" ]; then echo "task-edit guard: $f was deleted"; fail=1; continue; fi
  if ! diff -q <(git show "$base:$f" | norm) <(norm < "$cur") >/dev/null; then
    echo "task-edit guard: $cur changed beyond ticking checkboxes:"
    diff <(git show "$base:$f" | norm) <(norm < "$cur") | head -20 || true
    fail=1
  fi
done < <(git diff --name-only "$base" -- 'openspec/changes/*/tasks.md')

# progress.md is append-only: the base version must remain an exact prefix.
while IFS= read -r f; do
  git cat-file -e "$base:$f" 2>/dev/null || continue
  old=$(git show "$base:$f" | wc -c); cur=$(current "$f")
  if [ -z "$cur" ] || ! cmp -s -n "$old" <(git show "$base:$f") "$cur"; then
    echo "task-edit guard: $f is append-only, but earlier entries changed"; fail=1
  fi
done < <(git diff --name-only "$base" -- 'openspec/changes/*/progress.md')

[ "$fail" -eq 0 ] && echo "task-edit guard: OK ($branch)"
exit "$fail"
