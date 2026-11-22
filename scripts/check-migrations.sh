#!/usr/bin/env bash
# Migration guard: a database migration that has shipped must never change. A branch may only ADD
# files under the migrations directory; editing, deleting or renaming one fails, because deployed
# databases already applied it (checksum mismatch) and the history would no longer match.
# Usage: scripts/check-migrations.sh [base-ref]   (default origin/main; MIGRATIONS_DIR overrides the path)
set -euo pipefail
cd "$(dirname "$0")/.."
base="${1:-origin/main}"
dir="${MIGRATIONS_DIR:-services/control-plane/migrations}"
git rev-parse -q --verify "$base" >/dev/null || { echo "migration-guard: base ref $base not found (fetch it first)" >&2; exit 2; }
bad=$(git diff --name-status --no-renames "$base"...HEAD -- "$dir" | awk '$1 != "A"' || true)
if [ -n "$bad" ]; then
  echo "migration-guard: shipped migrations must not change; add a new migration instead:" >&2
  echo "$bad" >&2
  exit 1
fi
echo "migration-guard: OK"
