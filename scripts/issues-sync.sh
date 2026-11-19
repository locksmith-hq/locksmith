#!/usr/bin/env bash
# Runs the three issue syncs (change-sync, roadmap-sync, dates-sync) from a clean checkout of
# origin/main, so an agent can run it from any branch without its unmerged edits reaching GitHub.
# The lead runs this at the end of every run while the change-sync workflow is off (#316).
#   scripts/issues-sync.sh            DRY_RUN=1 prints the writes instead of making them
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git fetch -q origin main
d=$(mktemp -d)
trap 'git worktree remove --force "$d"' EXIT
git worktree add -q --detach "$d" origin/main
cd "$d"
for s in change-sync roadmap-sync dates-sync; do bash "scripts/$s.sh"; done
