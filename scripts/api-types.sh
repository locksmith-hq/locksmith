#!/usr/bin/env bash
# Generate apps/api/src/db/types.ts from a freshly migrated throwaway Postgres.
#   scripts/api-types.sh          regenerate the file
#   scripts/api-types.sh --check  fail (exit 1) if the committed file differs from the generated one
# Migrations stay owned by the Rust migrator: the `locksmith-migrate` binary applies them; apps/api
# only reads the schema (openspec change b1-nestjs-api, design.md "Migrations"). The Postgres runs in
# a docker container with a random password on a random loopback port and is removed on exit.
# PG_IMAGE overrides the image (default: the compose image).
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:-write}"
case "$mode" in write|--check) ;; *) echo "usage: $0 [--check]" >&2; exit 2 ;; esac

image="${PG_IMAGE:-$(sed -n 's/^ *image: *\(postgres:[^ ]*\)$/\1/p' infra/compose/compose.yaml | head -1)}"
[ -n "$image" ] || { echo "api-types: cannot find the postgres image in infra/compose/compose.yaml" >&2; exit 1; }
out=apps/api/src/db/types.ts
pw=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
name="locksmith-api-types-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; [ -z "${tmp:-}" ] || rm -f "$tmp"; }
trap cleanup EXIT

docker run -d --rm --name "$name" -e POSTGRES_PASSWORD="$pw" -e POSTGRES_DB=locksmith \
  -p 127.0.0.1::5432 "$image" >/dev/null
for _ in $(seq 1 60); do
  docker exec "$name" pg_isready -q -U postgres -d locksmith && break
  sleep 1
done
docker exec "$name" pg_isready -q -U postgres -d locksmith || { echo "api-types: postgres did not start" >&2; exit 1; }
# pg_isready can answer during the init-time restart; the TCP login is the real readiness check.
port=$(docker port "$name" 5432/tcp | head -1 | sed 's/.*://')
url="postgres://postgres:${pw}@127.0.0.1:${port}/locksmith"
for _ in $(seq 1 30); do
  PGPASSWORD="$pw" psql -q -h 127.0.0.1 -p "$port" -U postgres -d locksmith -c 'select 1' >/dev/null 2>&1 && break
  sleep 1
done

# The bootstrap superuser is the owner login for the first run (migration 0001 creates the roles).
DATABASE_OWNER_URL="$url" cargo run -q -p ls-control-plane --bin locksmith-migrate

tmp=$(mktemp "$PWD/apps/api/src/db/.types.XXXXXX.ts")
(cd apps/api && DATABASE_URL="$url" npx kysely-codegen --dialect postgres --url env\(DATABASE_URL\) \
  --exclude-pattern '_sqlx_migrations' --out-file "${tmp#"$PWD/apps/api/"}")

if [ "$mode" = "--check" ]; then
  if diff -u "$out" "$tmp" >/dev/null; then echo "api-types: $out is up to date"; exit 0; fi
  diff -u "$out" "$tmp" | head -60 || true
  echo "api-types: $out is stale; run 'just api-types' and commit the result" >&2
  exit 1
fi
mv "$tmp" "$out"; tmp=""
echo "api-types: wrote $out"
