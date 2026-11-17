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
expect 0 claude/lead-z "lead branch may edit agent rules"
echo x > docs/agents/merge.md; git add -A
expect 1 claude/lead-z "lead branch may not edit merge gates"
git rm -q --cached docs/agents/merge.md; rm docs/agents/merge.md
mkdir -p .claude/skills/run-start .claude/skills/merge-queue; echo x > .claude/skills/run-start/SKILL.md; git add -A
expect 0 claude/lead-z "lead branch may edit a skill"
expect 1 claude/change-c1b "worker branch may not edit a skill"
echo x > .claude/skills/merge-queue/SKILL.md; git add -A
expect 1 claude/lead-z "lead branch may not edit merge-queue skill"
git rm -rq --cached .claude; rm -rf .claude
mkdir -p .github/workflows; echo x > .github/workflows/ci.yml; git add -A
expect 1 claude/lead-z "lead branch may not edit workflows"
git checkout -q main; mkdir -p docs/agents; printf -- '- d1\n' > docs/agents/owner.md; git add -A; git commit -qm owner; git update-ref refs/remotes/origin/main HEAD
git switch -qc claude/change-o1; printf -- '- d2\n' >> docs/agents/owner.md; git add -A
expect 0 claude/change-o1 "agent may append to owner.md"
printf -- '- changed\n- d2\n' > docs/agents/owner.md; git add -A
expect 1 claude/change-o1 "agent may not rewrite owner.md"
git checkout -q -f main; git update-ref refs/remotes/origin/main HEAD; git switch -qc claude/change-c1c
mkdir -p openspec/changes/archive; git mv openspec/changes/c1 openspec/changes/archive/2026-01-01-c1
sed -i.bak 's/- \[ \]/- [x]/' openspec/changes/archive/2026-01-01-c1/tasks.md; rm -f openspec/changes/archive/2026-01-01-c1/*.bak
printf '## e3\n' >> openspec/changes/archive/2026-01-01-c1/progress.md; git add -A
expect 0 claude/change-c1c "archive in the finishing PR (ticks and append only)"
sed -i.bak 's/Do B/Do nothing/' openspec/changes/archive/2026-01-01-c1/tasks.md; git add -A
expect 1 claude/change-c1c "archive copy with edited task text"
git rm -rqf openspec/changes/archive
expect 1 claude/change-c1c "change deleted without archive"
echo "check-task-edits: all tests passed"
