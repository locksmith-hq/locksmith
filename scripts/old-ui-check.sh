#!/usr/bin/env bash
# One UI source: design-system/. Fails if the old kit, the console mockup or the old design spec is back,
# or if anything still names them (workflows and design-system/ are owner-reviewed and skipped).
set -euo pipefail

cd "$(dirname "$0")/.."
fail=0

for p in packages/ui apps/web/mockup.html apps/web/src/mockup DESIGN.md .impeccable apps/desktop/.impeccable; do
  if [ -e "$p" ]; then
    echo "old-ui-check: $p must not exist (the design system in design-system/ is the only UI source)" >&2
    fail=1
  fi
done

if hits=$(git grep -nE '@locksmith/ui|packages/ui|src/mockup|DESIGN\.md' -- . \
  ':(exclude).github/workflows' ':(exclude)design-system' ':(exclude)scripts/old-ui-check.sh'); then
  echo "old-ui-check: references to the old UI:" >&2
  echo "$hits" >&2
  fail=1
fi

exit "$fail"
