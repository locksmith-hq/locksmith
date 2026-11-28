#!/usr/bin/env bash
# Every manifest entry appears in the generated formula; bad input is rejected.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
command -v jq >/dev/null || { echo "SKIP gen-formula.test: jq missing (not a pass)"; exit 0; }
T="aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu"
mkdir "$tmp/d"; for t in $T; do echo "bin $t" > "$tmp/d/smith-$t"; done
"$here/make-manifest.sh" 1.2.3 "$tmp/d" >/dev/null
"$here/gen-formula.sh" "$tmp/d" > "$tmp/smith.rb"
for t in $T; do
  name="$(jq -r --arg t "$t" '.targets[$t].name' "$tmp/d/manifest.json")"
  sha="$(jq -r --arg t "$t" '.targets[$t].sha256' "$tmp/d/manifest.json")"
  grep -q "releases/download/v1.2.3/$name\"" "$tmp/smith.rb" || fail "url for $t"
  grep -q "sha256 \"$sha\"" "$tmp/smith.rb" || fail "sha for $t"
done
[ "$(grep -c 'sha256 "' "$tmp/smith.rb")" -eq 4 ] || fail "unexpected sha count"
grep -q 'version "1.2.3"' "$tmp/smith.rb" || fail "version"
# missing triple in manifest
jq 'del(.targets["x86_64-apple-darwin"])' "$tmp/d/manifest.json" > "$tmp/m" && mv "$tmp/m" "$tmp/d/manifest.json"
if "$here/gen-formula.sh" "$tmp/d" >/dev/null 2>&1; then fail "incomplete manifest accepted"; fi
echo "gen-formula.test: ok"
