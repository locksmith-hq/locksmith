#!/usr/bin/env bash
# Enforces the repo layout: Rust sources and package.json only where allowed.
set -euo pipefail

cd "$(dirname "$0")/.."
fail=0
prune=( \( -name target -o -name node_modules -o -name .git \) -prune -o )

while IFS= read -r f; do
  case "$f" in
    crates/*|services/*|apps/desktop/src-tauri/*) ;;
    *) echo "tree-check: Rust file outside crates/, services/ or apps/desktop/src-tauri/: $f" >&2; fail=1 ;;
  esac
done < <(find . "${prune[@]}" -name '*.rs' -type f -print | sed 's|^\./||')

while IFS= read -r f; do
  echo "tree-check: package.json not allowed under crates/ or services/: $f" >&2
  fail=1
done < <(find . "${prune[@]}" -name package.json -type f -print | sed 's|^\./||' | grep -E '^(crates|services)/' || true)

if [ "$fail" -ne 0 ]; then
  echo "tree-check: FAILED" >&2
  exit 1
fi
echo "tree-check: OK"
