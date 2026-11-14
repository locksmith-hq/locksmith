#!/usr/bin/env bash
# Usage: make-manifest.sh VERSION DIR
# Writes DIR/manifest.json describing every DIR/smith-<triple> asset.
set -euo pipefail

VERSION="${1:?usage: make-manifest.sh VERSION DIR}"
DIR="${2:?usage: make-manifest.sh VERSION DIR}"

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
else
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

# Names go into JSON unescaped, so only accept safe characters.
safe() { [[ "$1" =~ ^[A-Za-z0-9._+-]+$ ]] || { echo "make-manifest: unsafe value: $1" >&2; exit 1; }; }
safe "$VERSION"

rows=""
count=0
for f in "$DIR"/smith-*; do
  [ -f "$f" ] || continue
  name="$(basename "$f")"
  triple="${name#smith-}"
  safe "$triple"
  rows+="$triple"$'\t'"$name"$'\t'"$(sha256 "$f")"$'\n'
  count=$((count + 1))
done
[ "$count" -gt 0 ] || { echo "make-manifest: no $DIR/smith-* files found" >&2; exit 1; }

out="$DIR/manifest.json"
if command -v jq >/dev/null 2>&1; then
  printf '%s' "$rows" | jq -Rn --arg v "$VERSION" '
    {version: $v,
     targets: ([inputs | select(length > 0) | split("\t")
                | {key: .[0], value: {name: .[1], sha256: .[2]}}] | from_entries)}' > "$out"
else
  {
    printf '{"version":"%s","targets":{' "$VERSION"
    sep=""
    while IFS=$'\t' read -r triple name digest; do
      [ -n "$triple" ] || continue
      printf '%s"%s":{"name":"%s","sha256":"%s"}' "$sep" "$triple" "$name" "$digest"
      sep=","
    done <<< "$rows"
    printf '}}\n'
  } > "$out"
fi

echo "make-manifest: wrote $out ($count targets)"
