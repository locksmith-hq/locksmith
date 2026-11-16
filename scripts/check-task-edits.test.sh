#!/usr/bin/env bash
# Self-test for check-task-edits.sh in a throwaway git repo: tick passes, text edit fails,
# planning branch skips, new change passes.
set -euo pipefail
guard="$(cd "$(dirname "$0")" && pwd)/check-task-edits.sh"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cd "$tmp"; git init -q -b main; git config user.email t@t; git config user.name t
mkdir -p openspec/changes/c1; printf -- '- [ ] 1.1 Do A\n- [ ] 1.2 Do B\n' > openspec/changes/c1/tasks.md
git add -A; git commit -qm base; git update-ref refs/remotes/origin/main HEAD
git switch -qc claude/change-c1

expect() { if BRANCH="$2" bash "$guard" >/dev/null 2>&1; then got=0; else got=1; fi
  [ "$got" = "$1" ] || { echo "FAIL: $3 (expected exit $1, got $got)"; exit 1; }; echo "ok: $3"; }

sed -i.bak 's/- \[ \] 1.1/- [x] 1.1/' openspec/changes/c1/tasks.md; expect 0 claude/change-c1 "tick only"
sed -i.bak 's/Do B/Do nothing/' openspec/changes/c1/tasks.md;      expect 1 claude/change-c1 "text edit"
expect 0 claude/planning-x "planning branch skips"
git checkout -q -- openspec/changes/c1/tasks.md
mkdir -p openspec/changes/c2; printf -- '- [ ] 1.1 New\n' > openspec/changes/c2/tasks.md
git add -A; expect 0 claude/change-c1 "new change file"
git checkout -q main; printf '# log\n## e1\n' > openspec/changes/c1/progress.md; git add -A; git commit -qm log
git update-ref refs/remotes/origin/main HEAD; git switch -qc claude/change-c1b
printf '## e2\n' >> openspec/changes/c1/progress.md; expect 0 claude/change-c1b "progress append"
printf '# log\n## edited\n## e2\n' > openspec/changes/c1/progress.md; expect 1 claude/change-c1b "progress rewrite"
git checkout -q -- openspec/changes/c1/progress.md
mkdir -p docs/agents; echo x > docs/agents/worker.md; git add -A
expect 1 claude/change-c1b "agent edits its own rules"
expect 1 claude/planning-y "planning branch edits agent rules"
expect 0 human-branch "human branch may edit agent rules"
expect 0 claude/learning-z "learning branch may edit agent rules"
mkdir -p .github/workflows; echo x > .github/workflows/ci.yml; git add -A
expect 1 claude/learning-z "learning branch may not edit workflows"
echo "check-task-edits: all tests passed"
