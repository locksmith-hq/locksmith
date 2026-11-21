#!/usr/bin/env bash
# Tests scripts/make-manifest.sh: required triples, name safety, SBOM and image list.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
T="aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu"
mk() { rm -rf "$1"; mkdir -p "$1"; for t in ${2:-$T}; do echo "bin $t" > "$1/smith-$t"; done; }
digest="sha256:$(printf 'a%.0s' $(seq 64))"

# good: four triples
mk "$tmp/ok"
"$here/make-manifest.sh" 1.2.3 "$tmp/ok" >/dev/null
for t in $T; do
  want="$(sha256sum "$tmp/ok/smith-$t" | awk '{print $1}')"
  grep -q "$want" "$tmp/ok/manifest.json" || fail "digest for $t missing"
done

# missing triple is rejected, allowed with --allow-partial
mk "$tmp/part" "aarch64-apple-darwin"
if "$here/make-manifest.sh" 1.2.3 "$tmp/part" >/dev/null 2>&1; then fail "partial set accepted"; fi
"$here/make-manifest.sh" 1.2.3 "$tmp/part" --allow-partial >/dev/null || fail "--allow-partial rejected"

# unsafe names and versions
mk "$tmp/bad"; echo x > "$tmp/bad/smith-evil\"name"
if "$here/make-manifest.sh" 1.2.3 "$tmp/bad" >/dev/null 2>&1; then fail "unsafe name accepted"; fi
mk "$tmp/ver"
if "$here/make-manifest.sh" '1"2' "$tmp/ver" >/dev/null 2>&1; then fail "unsafe version accepted"; fi

# SBOM and image list
if command -v jq >/dev/null 2>&1; then
  mk "$tmp/sb"
  echo '{"bomFormat":"CycloneDX","specVersion":"1.5"}' > "$tmp/sbom.json"
  echo "ghcr.io/locksmith-hq/gateway@$digest" > "$tmp/images.txt"
  "$here/make-manifest.sh" 1.2.3 "$tmp/sb" --sbom "$tmp/sbom.json" --images "$tmp/images.txt" >/dev/null
  [ -f "$tmp/sb/sbom.cdx.json" ] && [ -f "$tmp/sb/images.txt" ] || fail "sbom/images not emitted"
  echo '{"nope":1}' > "$tmp/badsbom.json"
  if "$here/make-manifest.sh" 1.2.3 "$tmp/sb" --sbom "$tmp/badsbom.json" >/dev/null 2>&1; then fail "non-CycloneDX SBOM accepted"; fi
  echo "gateway:latest" > "$tmp/badimg.txt"
  if "$here/make-manifest.sh" 1.2.3 "$tmp/sb" --images "$tmp/badimg.txt" >/dev/null 2>&1; then fail "undigested image accepted"; fi
else
  echo "SKIP: jq absent, sbom checks not run"
fi
echo "make-manifest.test.sh: ok"
