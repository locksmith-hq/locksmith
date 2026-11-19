#!/usr/bin/env bash
# Self-test for change-status.sh in a throwaway git repo (no GitHub calls).
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/change-status.sh"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cd "$tmp"; git init -q -b main; git config user.email t@t; git config user.name t
mkdir -p docs openspec/changes/archive/2026-01-01-a0-base
# shellcheck disable=SC2016 # literal backticks
printf '| `a0-base` |\n| `s1-api` |\n| `s2-crypto` |\n| `t1-auth` |\n| `w1-site` |\n' > docs/roadmap.md
mk() { mkdir -p "openspec/changes/$1"; printf 'schema: spec-driven\n%s\n' "$2" > "openspec/changes/$1/.openspec.yaml"; printf "%b" "$3" > "openspec/changes/$1/tasks.md"; }
mk s1-api    'x-depends_on: [a0-base]'        '- [x] 1.1 a\n- [ ] 1.2 b\n'
mk s2-crypto 'x-depends_on: [s1-api]'         '- [ ] 1.1 a\n'
mk t1-auth   'x-depends_on: [a0-base, s1-api]' '- [x] 1.1 a\n'
mk w1-site   ''                             '- [ ] 1.1 a\n'
# shellcheck disable=SC2016 # literal backticks
printf '| # | Change | Usable outcome | Needs |\n| N1 | `n1-new` | x | - |\n| N2 | `n2-later` | x | s2-crypto |\n| N3 | `n3-on-s1` | x | a0-base, s1-api |\n| S1 | `s1-api` | x | - |\n' >> docs/roadmap.md
git add -A; git commit -qm base; git update-ref refs/remotes/origin/main HEAD

expect() { got=$(OFFLINE=1 BLOCKERS="${3:-}" bash "$script" | awk -F'\t' -v id="$1" '$1==id{print $2" "$3}' | sed 's/ $//')
  [ "$got" = "$2" ] || { echo "FAIL: $1 expected '$2', got '$got'"; exit 1; }; echo "ok: $1 $2"; }

expect s1-api "ready"
expect s2-crypto "blocked needs s1-api"
expect t1-auth "finished"
expect w1-site "ready"
# s1's branch has every task ticked: s1 is in review, s2 may stack on it.
git switch -qc claude/change-s1-api; sed -i.bak 's/- \[ \] 1.2/- [x] 1.2/' openspec/changes/s1-api/tasks.md; rm -f openspec/changes/s1-api/*.bak
git commit -qam tick; git update-ref refs/remotes/origin/claude/change-s1-api HEAD; git switch -q main
expect s1-api "review"
expect s2-crypto "stackable on s1-api"
# s1's branch archives the change inside its PR: still in review, not ready again.
git switch -q claude/change-s1-api; git mv openspec/changes/s1-api openspec/changes/archive/2026-01-02-s1-api
git commit -qam archive; git update-ref refs/remotes/origin/claude/change-s1-api HEAD; git switch -q main
expect s1-api "review"
expect s2-crypto "stackable on s1-api"
expect w1-site "parked owner #7" "7 owner Need a domain for w1-site landing"
expect w1-site "parked rescue #8" "8 rescue Rescue: w1-site 1.1"
expect w1-site "parked owner #7" "$(printf '8 rescue Rescue: w1-site 1.1\n7 owner Need a domain for w1-site')"
[ "$(OFFLINE=1 BLOCKERS='7 owner w1-site' bash "$script" --ready | tr '\n' ' ')" = "s2-crypto " ] || { echo "FAIL: --ready"; exit 1; }
echo "ok: --ready lists only takeable changes"
# Unwritten rows whose Needs are archived or fully ticked on a branch; written rows (s1) never.
[ "$(bash "$script" --plannable | tr '\n' ' ')" = "n1-new n3-on-s1 " ] || { echo "FAIL: --plannable, got '$(bash "$script" --plannable | tr '\n' ' ')'"; exit 1; }
echo "ok: --plannable lists unwritten rows that can start"
echo "change-status: all tests passed"
