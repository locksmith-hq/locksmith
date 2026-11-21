#!/usr/bin/env bash
# Enforces the repo layout: Rust sources and package.json only where allowed.
set -euo pipefail

cd "$(dirname "$0")/.."
fail=0
prune=( \( -name target -o -name node_modules -o -name .git \) -prune -o )

while IFS= read -r f; do
  case "$f" in
    crates/*|services/*|apps/desktop/src-tauri/*|tests/e2e/*) ;;
    *) echo "tree-check: Rust file outside crates/, services/, tests/e2e/ or apps/desktop/src-tauri/: $f" >&2; fail=1 ;;
  esac
done < <(find . "${prune[@]}" -name '*.rs' -type f -print | sed 's|^\./||')

while IFS= read -r f; do
  echo "tree-check: package.json not allowed under crates/ or services/: $f" >&2
  fail=1
done < <(find . "${prune[@]}" -name package.json -type f -print | sed 's|^\./||' | grep -E '^(crates|services)/' || true)

# Every workflow job needs timeout-minutes: GitHub's default is 6 hours, and a stuck job burns quota.
while IFS= read -r j; do
  echo "tree-check: workflow job without timeout-minutes: $j" >&2
  fail=1
done < <(for w in .github/workflows/*.yml; do
  awk -v f="$w" '/^jobs:/{j=1; next} /^[^ #]/{j=0}
    j && /^  [A-Za-z0-9_-]+:[[:space:]]*$/{if (job && !t) print f": "job; job=$1; t=0}
    j && /^    timeout-minutes:/{t=1} END{if (job && !t) print f": "job}' "$w"
done)

# infra/tofu holds only the three root modules and the plan policy.
if [ -d infra/tofu ]; then
  for d in infra/tofu/*/; do
    case "$(basename "$d")" in
      guardrails|base|session|policy) ;;
      *) echo "tree-check: unexpected infra/tofu directory (allowed: guardrails, base, session, policy): $d" >&2; fail=1 ;;
    esac
  done
fi

# docs/testing.md must have a row per component directory.
bash scripts/test-recipes-check.sh || fail=1

if [ "$fail" -ne 0 ]; then
  echo "tree-check: FAILED" >&2
  exit 1
fi
echo "tree-check: OK"
