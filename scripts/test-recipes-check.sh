#!/usr/bin/env bash
# Keeps docs/testing.md in step with the repo: a row per component directory, no stale rows, and
# every `just` recipe named in the Dev environment section exists. Usage: test-recipes-check.sh [root]
set -uo pipefail
root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$root" || exit 2
doc=docs/testing.md
[ -f "$doc" ] || { echo "test-recipes: $doc missing" >&2; exit 1; }
fail=0

# Component directories: one level under these, plus the three test suites.
dirs=$(for d in crates/* services/* apps/* packages/* integrations/*; do [ -d "$d" ] && echo "$d"; done
  for d in tests/e2e tests/adversarial tests/kit; do [ -d "$d" ] && echo "$d"; done)
rows=$(sed -n 's/^| `\([a-z0-9_/.-]*\)` |.*/\1/p' "$doc")

for d in $dirs; do
  grep -qxF "$d" <<<"$rows" || { echo "test-recipes: no row in $doc for $d" >&2; fail=1; }
done
for r in $rows; do
  [ -d "$r" ] || { echo "test-recipes: stale row in $doc: $r does not exist" >&2; fail=1; }
done

# `just <recipe>` mentioned in the Dev environment section must exist in the justfile.
# Parsed from the justfile text: CI runners do not have `just` installed.
recipes=$(sed -n 's/^\([a-z][a-z0-9-]*\)\( [^:=]*\)\{0,1\}:\([^=].*\)\{0,1\}$/\1/p' justfile)
for rec in $(sed -n '/^## Dev environment/,$p' "$doc" | grep -o '`just [a-z][a-z0-9-]*' | sed 's/`just //' | sort -u); do
  grep -qxF "$rec" <<<"$recipes" || { echo "test-recipes: just recipe '$rec' named in $doc does not exist" >&2; fail=1; }
done

[ "$fail" -eq 0 ] && echo "test-recipes: OK" || { echo "test-recipes: FAILED" >&2; exit 1; }
