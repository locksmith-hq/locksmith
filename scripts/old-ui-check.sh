#!/usr/bin/env bash
# One UI source: design-system/. Fails if any part of the old UI is back.
# Usage: old-ui-check.sh [repo-root]   (default: this repo)
set -uo pipefail
root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$root" || exit 2
fail=0
for p in packages/ui DESIGN.md .impeccable apps/desktop/.impeccable apps/desktop/src/styles.css apps/web/src/console/legacy.css; do
  if [ -e "$p" ]; then echo "old-ui-check: old UI path exists: $p" >&2; fail=1; fi
done
if git rev-parse --git-dir >/dev/null 2>&1; then
  hits=$(git grep -nE '@locksmith/ui|packages/ui|src/mockup|DESIGN\.md' -- . ':!.github/workflows' ':!design-system' ':!scripts/old-ui-check.sh' ':!scripts/old-ui-check.test.sh')
  if [ -n "$hits" ]; then echo "old-ui-check: reference to the old UI:" >&2; echo "$hits" >&2; fail=1; fi
fi
exit $fail
