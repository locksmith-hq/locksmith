#!/usr/bin/env bash
# Usage: make-manifest.sh VERSION DIR [--allow-partial] [--sbom FILE] [--images FILE]
# Writes DIR/manifest.json describing every DIR/smith-<triple> asset.
# All four release triples are required unless --allow-partial (local dry runs).
# --sbom FILE copies a CycloneDX JSON SBOM to DIR/sbom.cdx.json (must parse).
# --images FILE copies the image digest list (lines of <name>@sha256:<64 hex>)
# to DIR/images.txt.
set -euo pipefail

USAGE="usage: make-manifest.sh VERSION DIR [--allow-partial] [--sbom FILE] [--images FILE]"
VERSION="${1:?$USAGE}"
DIR="${2:?$USAGE}"
shift 2
PARTIAL=0 SBOM="" IMAGES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-partial) PARTIAL=1; shift ;;
    --sbom) SBOM="${2:?$USAGE}"; shift 2 ;;
    --images) IMAGES="${2:?$USAGE}"; shift 2 ;;
    *) echo "make-manifest: unknown option: $1" >&2; exit 2 ;;
  esac
done
REQUIRED_TRIPLES="aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu"

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
if [ "$PARTIAL" -eq 0 ]; then
  for t in $REQUIRED_TRIPLES; do
    [ -f "$DIR/smith-$t" ] || { echo "make-manifest: missing required asset smith-$t" >&2; exit 1; }
  done
fi

if [ -n "$SBOM" ]; then
  [ -f "$SBOM" ] || { echo "make-manifest: SBOM not found: $SBOM" >&2; exit 1; }
  command -v jq >/dev/null 2>&1 || { echo "make-manifest: jq is required to validate the SBOM" >&2; exit 1; }
  jq -e '.bomFormat == "CycloneDX"' "$SBOM" >/dev/null 2>&1 \
    || { echo "make-manifest: SBOM is not a CycloneDX JSON document" >&2; exit 1; }
  cp "$SBOM" "$DIR/sbom.cdx.json"
fi
if [ -n "$IMAGES" ]; then
  [ -s "$IMAGES" ] || { echo "make-manifest: image digest list missing or empty: $IMAGES" >&2; exit 1; }
  grep -Eqv '^[A-Za-z0-9./_-]+(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$' "$IMAGES" \
    && { echo "make-manifest: bad line in image digest list (want name@sha256:<64 hex>)" >&2; exit 1; }
  cp "$IMAGES" "$DIR/images.txt"
fi

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
