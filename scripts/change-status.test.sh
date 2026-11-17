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
expect w1-site "parked owner #7" "7 owner Need a domain for w1-site landing"
expect w1-site "parked rescue #8" "8 rescue Rescue: w1-site 1.1"
expect w1-site "parked owner #7" "$(printf '7 owner Need a domain for w1-site\n8 rescue Rescue: w1-site 1.1')"
[ "$(OFFLINE=1 BLOCKERS='7 owner w1-site' bash "$script" --ready | tr '\n' ' ')" = "s2-crypto " ] || { echo "FAIL: --ready"; exit 1; }
echo "ok: --ready lists only takeable changes"
echo "change-status: all tests passed"
