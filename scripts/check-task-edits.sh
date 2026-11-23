#!/usr/bin/env bash
# Guard: on implementation branches (claude/change-*, change/*) an agent may only tick or untick
# OpenSpec tasks, never edit, add or remove task text. Planning branches may edit freely.
# Why: Anthropic's long-running-agent harness found models rewrite Markdown task lists to look done
# (https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents).
# Usage: BRANCH=<name> scripts/check-task-edits.sh   (BRANCH defaults to the current git branch)
set -euo pipefail

branch="${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"

# Two rules for the agent system (owner 2026-11-19, Agent System v3, #470):
# 1. Weekly release: agent-system files change only on a *harness-release-* branch (one PR a week, built by the
#    optimizer, approved by the owner) or a *hotfix-* branch (red main, a security fix, every run failing).
#    This binds every branch, owner sessions included; other findings go to the harness-backlog issue.
# 2. Trust root: agents (claude/* branches) never change the gates, guards, routing, workflows or hard rules.
trust=(.github/workflows .github/CODEOWNERS 'scripts/check-task-edits*' scripts/check-agent-docs.sh
       scripts/route.sh scripts/dispatch.sh scripts/review-tier.sh docs/agents/routing.json docs/agents/common.md docs/agents/merge.md .claude/skills/merge-review
       AGENTS.md CLAUDE.md openspec/config.yaml .claude/settings.json .claude/settings.local.json .claude/agents)
harness=("${trust[@]}" docs/agents .claude/skills scripts/run-lock.sh scripts/worker-has-work.sh scripts/owner-replies.sh
         scripts/change-status.sh scripts/change-issue.sh scripts/change-sync.sh scripts/roadmap-sync.sh scripts/issue-lib.sh
         scripts/dates-sync.sh scripts/issues-sync.sh scripts/run-meta.sh scripts/request-work.sh scripts/agent-start.sh scripts/agent-preflight.sh scripts/bg.sh)
protected_fail=0
# Append-only files: no line of the base version is removed or changed. New lines may sit anywhere, so a
# `merge=union` merge (.gitattributes) of two branches that both appended still passes.
kept() { ! grep -q '^<' <(diff <(git show "$1") "$2"); }   # <rev:path> <file>
if git rev-parse -q --verify origin/main >/dev/null; then
  ob=$(git merge-base HEAD origin/main)
  # owner.md (owner decisions) may be appended on any branch; it is not part of the weekly release.
  changed=$(git diff --name-only "$ob" -- "${harness[@]}" | grep -v '^docs/agents/owner.md$' || true)
  case "$branch" in *harness-release-*|*hotfix-*) ;; *)
    if [ -n "$changed" ]; then
      echo "task-edit guard: '$branch' changes agent-system files outside the weekly release:"; echo "$changed"
      echo "  Add the finding to the harness-backlog issue, or use a *hotfix-* branch for red main, a security fix or every run failing."
      protected_fail=1
    fi ;;
  esac
  if [[ "$branch" == claude/* ]]; then
    # owner.md and openspec/decisions.md: agents may only append (new owner decisions), never edit existing lines.
    for f in docs/agents/owner.md openspec/decisions.md; do
      if git cat-file -e "$ob:$f" 2>/dev/null; then
        { [ -f "$f" ] && kept "$ob:$f" "$f"; } || { echo "task-edit guard: $f is append-only for agents"; protected_fail=1; }
      fi
    done
    # The weekly release may carry trust-root fixes: every trust path is in CODEOWNERS, so merge-ready waits for
    # the owner's approval. Before 2026-11-22 they went into the PR body as prose and were never applied (W1).
    tchanged=$(git diff --name-only "$ob" -- "${trust[@]}" || true)
    if [ -n "$tchanged" ] && [[ "$branch" != *harness-release-* ]]; then
      echo "task-edit guard: agent branch '$branch' changed trust-root files (owner-only):"; echo "$tchanged"
      protected_fail=1
    fi
    # A cloud session's commits carry its App identity. One without it acts as the owner (pre-persona sessions, #573).
    # Logins come from main's routing.json (never the branch's copy), so an App rename there cannot break this (#645).
    case "$branch" in *harness-release-*|*hotfix-*) ;; *)
      logins=$(git show origin/main:docs/agents/routing.json | jq -r '.roles|to_entries[]|select(.key != "owner")|.value.logins[]?')
      bad=$(git log --no-merges --since=2026-11-22T06:00:00Z --format='%h|%an|%(trailers:key=Claude-Session,valueonly,separator=%x20)' "$ob"..HEAD |
        awk -F'|' -v ok="$(tr "\n" " " <<<"$logins")" 'BEGIN{n=split(ok,a," "); for(i=1;i<=n;i++) bot[a[i]]=1} $3!="" && !($2 in bot){print $1" by "$2}')
      if [ -n "$bad" ]; then
        echo "task-edit guard: commits from a session without its App identity (archive that session):"; echo "$bad"
        protected_fail=1
      fi ;;
    esac
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

# progress.md is append-only: every earlier line stays, unchanged and in order.
while IFS= read -r f; do
  git cat-file -e "$base:$f" 2>/dev/null || continue
  cur=$(current "$f")
  if [ -z "$cur" ] || ! kept "$base:$f" "$cur"; then
    echo "task-edit guard: $f is append-only, but earlier entries changed"; fail=1
  fi
done < <(git diff --name-only "$base" -- 'openspec/changes/*/progress.md')

[ "$fail" -eq 0 ] && echo "task-edit guard: OK ($branch)"
exit "$fail"
