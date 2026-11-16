#!/usr/bin/env bash
# Guard: on implementation branches (claude/change-*, change/*) an agent may only tick or untick
# OpenSpec tasks, never edit, add or remove task text. Planning branches may edit freely.
# Why: Anthropic's long-running-agent harness found models rewrite Markdown task lists to look done
# (https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents).
# Usage: BRANCH=<name> scripts/check-task-edits.sh   (BRANCH defaults to the current git branch)
set -euo pipefail

branch="${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"

# Agents (claude/* branches) may never change their own rules, CI, or this guard.
# Exception: claude/learning-* may propose edits to agent instructions and run-meta (owner merges);
# workflows, this guard, CLAUDE.md, openspec/config.yaml and .claude/ stay owner-only for everyone.
protected_fail=0
if [[ "$branch" == claude/* ]] && git rev-parse -q --verify origin/main >/dev/null; then
  paths=(.github/workflows 'scripts/check-task-edits*' CLAUDE.md openspec/config.yaml .claude docs/agents/merge.md docs/agents/common.md)
  [[ "$branch" == claude/learning-* ]] || paths+=(docs/agents scripts/run-meta.sh)
  changed=$(git diff --name-only "$(git merge-base HEAD origin/main)" -- "${paths[@]}")
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

fail=$protected_fail
while IFS= read -r f; do
  git cat-file -e "$base:$f" 2>/dev/null || continue   # a new tasks.md (new change) is allowed
  if [ ! -f "$f" ]; then echo "task-edit guard: $f was deleted"; fail=1; continue; fi
  if ! diff -q <(git show "$base:$f" | norm) <(norm < "$f") >/dev/null; then
    echo "task-edit guard: $f changed beyond ticking checkboxes:"
    diff <(git show "$base:$f" | norm) <(norm < "$f") | head -20 || true
    fail=1
  fi
done < <(git diff --name-only "$base" -- 'openspec/changes/*/tasks.md')

# progress.md is append-only: the base version must remain an exact prefix.
while IFS= read -r f; do
  git cat-file -e "$base:$f" 2>/dev/null || continue
  old=$(git show "$base:$f" | wc -c)
  if [ ! -f "$f" ] || ! cmp -s -n "$old" <(git show "$base:$f") "$f"; then
    echo "task-edit guard: $f is append-only, but earlier entries changed"; fail=1
  fi
done < <(git diff --name-only "$base" -- 'openspec/changes/*/progress.md')

[ "$fail" -eq 0 ] && echo "task-edit guard: OK ($branch)"
exit "$fail"
