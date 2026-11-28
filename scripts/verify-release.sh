#!/usr/bin/env bash
# Usage: verify-release.sh DIR [--pubkey FILE] [--identity-regexp RE] [--skip-cosign]
# Verifies a release directory: minisign signature of manifest.json, SHA-256 of
# every asset against the manifest, cosign keyless bundle of the manifest with the
# expected workflow identity, and a parseable SBOM. One result line per check;
# non-zero on any failure. --skip-cosign (local dry runs only) prints a SKIP line.
set -uo pipefail

USAGE="usage: verify-release.sh DIR [--pubkey FILE] [--identity-regexp RE] [--skip-cosign]"
DIR="${1:?$USAGE}"
shift
here="$(cd "$(dirname "$0")" && pwd)"
PUBKEY="$here/../crates/ls-update/update-pubkey.txt"
IDENTITY='^https://github.com/locksmith-hq/locksmith/\.github/workflows/release\.yml@refs/tags/.+$'
ISSUER="https://token.actions.githubusercontent.com"
SKIP_COSIGN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --pubkey) PUBKEY="${2:?$USAGE}"; shift 2 ;;
    --identity-regexp) IDENTITY="${2:?$USAGE}"; shift 2 ;;
    --skip-cosign) SKIP_COSIGN=1; shift ;;
    *) echo "verify-release: unknown option: $1" >&2; exit 2 ;;
  esac
done

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
else
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

failed=0
ok() { echo "OK   $*"; }
bad() { echo "FAIL $*"; failed=1; }

MANIFEST="$DIR/manifest.json"
[ -f "$MANIFEST" ] || { echo "FAIL manifest.json missing in $DIR"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "FAIL jq is required"; exit 1; }
command -v minisign >/dev/null 2>&1 || { echo "FAIL minisign is required"; exit 1; }
[ -f "$PUBKEY" ] || { echo "FAIL public key not found: $PUBKEY"; exit 1; }

# 1. minisign signature over the manifest.
if minisign -V -P "$(tr -d '[:space:]' < "$PUBKEY")" -m "$MANIFEST" -x "$MANIFEST.minisig" >/dev/null 2>&1; then
  ok "manifest.json minisign signature"
else
  bad "manifest.json minisign signature"
fi

# 2. every asset against the manifest (also reject listed names that are unsafe).
checked=0
while IFS=$'\t' read -r name want; do
  [ -n "$name" ] || continue
  if ! [[ "$name" =~ ^[A-Za-z0-9._+-]+$ ]]; then bad "$name unsafe asset name"; continue; fi
  if [ ! -f "$DIR/$name" ]; then bad "$name missing"; continue; fi
  checked=$((checked + 1))
  got="$(sha256 "$DIR/$name")"
  if [ "$got" = "$want" ]; then ok "$name sha256"; else bad "$name sha256 mismatch"; fi
done < <(jq -r '.targets | to_entries[] | [.value.name, .value.sha256] | @tsv' "$MANIFEST")

[ "$checked" -gt 0 ] || bad "manifest lists no verifiable assets"

# 3. cosign keyless bundle over the manifest, expected workflow identity.
if [ "$SKIP_COSIGN" -eq 1 ]; then
  echo "SKIP manifest.json cosign (--skip-cosign, not for releases)"
elif ! command -v cosign >/dev/null 2>&1; then
  bad "manifest.json cosign (cosign not installed; use --skip-cosign only for local dry runs)"
elif cosign verify-blob --bundle "$MANIFEST.bundle" \
    --certificate-identity-regexp "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" "$MANIFEST" >/dev/null 2>&1; then
  ok "manifest.json cosign identity"
else
  bad "manifest.json cosign identity"
fi

# 4. SBOM present and parseable.
if jq -e '.bomFormat == "CycloneDX"' "$DIR/sbom.cdx.json" >/dev/null 2>&1; then
  ok "sbom.cdx.json parses"
else
  bad "sbom.cdx.json missing or not CycloneDX JSON"
fi

exit "$failed"
