#!/usr/bin/env bash
# Plants an old-UI file in a temp git repo and checks that old-ui-check.sh passes clean and fails planted.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
git init -q "$tmp" && cd "$tmp" && mkdir -p apps/web && echo ok > apps/web/a.txt && git add -A
bash "$here/old-ui-check.sh" "$tmp" 2>/dev/null && echo "ok: clean tree passes" || { echo "FAIL: clean tree"; fail=1; }
mkdir -p packages/ui/src && echo x > packages/ui/src/kit.tsx
bash "$here/old-ui-check.sh" "$tmp" 2>/dev/null && { echo "FAIL: planted kit.tsx passes"; fail=1; } || echo "ok: planted packages/ui/src/kit.tsx fails"
rm -rf packages
echo "see DESIGN.md" > apps/web/b.txt && git add -A
bash "$here/old-ui-check.sh" "$tmp" 2>/dev/null && { echo "FAIL: planted reference passes"; fail=1; } || echo "ok: planted reference fails"
exit $fail
