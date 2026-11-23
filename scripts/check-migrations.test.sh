#!/usr/bin/env bash
# Tests for check-migrations.sh in a scratch git repository.
set -euo pipefail
guard="$(cd "$(dirname "$0")" && pwd)/check-migrations.sh"
pass=0; fail=0
ok() { echo "PASS  $1"; pass=$((pass+1)); }
no() { echo "FAIL  $1"; fail=$((fail+1)); }
new() {
  S=$(mktemp -d); mkdir -p "$S/scripts" "$S/m"; cp "$guard" "$S/scripts/check-migrations.sh"
  ( cd "$S" && git init -q -b main && git config user.email t@t && git config user.name t \
    && echo "select 1;" > m/0001.sql && git add -A && git commit -qm base && git checkout -q -b work )
}
run() { ( cd "$1" && MIGRATIONS_DIR=m bash scripts/check-migrations.sh main >/dev/null 2>&1 ); }

new; ( cd "$S" && echo "select 2;" > m/0002.sql && git add -A && git commit -qm add )
if run "$S"; then ok "adding a migration passes"; else no "adding a migration passes"; fi; rm -rf "$S"

new; ( cd "$S" && echo "select 9;" > m/0001.sql && git commit -qam edit )
if run "$S"; then no "editing a shipped migration fails"; else ok "editing a shipped migration fails"; fi; rm -rf "$S"

new; ( cd "$S" && git rm -q m/0001.sql && git commit -qm del )
if run "$S"; then no "deleting a shipped migration fails"; else ok "deleting a shipped migration fails"; fi; rm -rf "$S"

new; ( cd "$S" && git mv m/0001.sql m/0001_renamed.sql && git commit -qm mv )
if run "$S"; then no "renaming a shipped migration fails"; else ok "renaming a shipped migration fails"; fi; rm -rf "$S"

new
if run "$S"; then ok "no change passes"; else no "no change passes"; fi; rm -rf "$S"

echo "migration-guard tests: $pass passed, $fail failed"; [ "$fail" -eq 0 ]
