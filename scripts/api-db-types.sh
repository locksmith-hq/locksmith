#!/usr/bin/env bash
# Regenerate apps/api/src/db/types.ts from the migrated database (kysely-codegen).
# Migrations stay owned by the Rust `migrate` binary; here they are only applied to a throwaway
# Postgres so the generated types match them. `--check` fails if the committed file differs.
set -euo pipefail
cd "$(dirname "$0")/.."
name="ls-api-types-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" -e POSTGRES_PASSWORD=pw -e POSTGRES_USER=locksmith -e POSTGRES_DB=locksmith \
  -p 127.0.0.1::5432 "${POSTGRES_IMAGE:-postgres:18.7}" >/dev/null
port=$(docker port "$name" 5432/tcp | head -1 | sed 's/.*://')
for _ in $(seq 60); do
  docker exec "$name" pg_isready -q -U locksmith -d locksmith 2>/dev/null && break
  sleep 1
done
sleep 2
for f in services/control-plane/migrations/*.sql; do
  docker exec -i "$name" psql -q -v ON_ERROR_STOP=1 -U locksmith -d locksmith <"$f" >/dev/null
done
out=apps/api/src/db/types.ts
tmp=$(mktemp)
(cd apps/api && DATABASE_URL="postgres://locksmith:pw@127.0.0.1:$port/locksmith" \
  npx --no-install kysely-codegen --dialect postgres --out-file "$tmp" >/dev/null)
if [ "${1:-}" = "--check" ]; then
  diff -u "$out" "$tmp" >/dev/null || { echo "api-db-types: $out is out of date; run 'just api-db-types'" >&2; rm -f "$tmp"; exit 1; }
  rm -f "$tmp"
else
  mv "$tmp" "$out"
fi
