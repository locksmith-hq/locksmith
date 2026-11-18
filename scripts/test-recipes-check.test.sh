#!/usr/bin/env bash
# Plants each failure in a temp copy and checks that test-recipes-check.sh catches it.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
fresh() { rm -rf "$tmp/r"; mkdir "$tmp/r"; cp -r "$here/docs" "$here/justfile" "$tmp/r/"
  for d in crates services apps packages integrations tests; do
    (cd "$here" && find "$d" -maxdepth 2 -type d \( -name target -o -name node_modules \) -prune -o -type d -print) | while read -r p; do mkdir -p "$tmp/r/$p"; done
  done; }
run() { bash "$here/scripts/test-recipes-check.sh" "$tmp/r" 2>&1; }
expect() { # <label> <pattern>
  out=$(run); rc=$?
  if [ $rc -ne 0 ] && grep -q "$2" <<<"$out"; then echo "ok: $1"; else echo "FAIL: $1 (rc=$rc): $out"; fail=1; fi; }

fresh; out=$(run) && echo "ok: clean copy passes" || { echo "FAIL: clean copy: $out"; fail=1; }
fresh; mkdir -p "$tmp/r/crates/ls-planted"; expect "missing row" "no row in docs/testing.md for crates/ls-planted"
fresh; rmdir "$tmp/r/crates/ls-core" 2>/dev/null || rm -rf "$tmp/r/crates/ls-core"; expect "stale row" "stale row.*crates/ls-core"
fresh; echo 'Run `just no-such-recipe` too.' >> "$tmp/r/docs/testing.md"; expect "unknown just recipe" "no-such-recipe"
exit $fail
