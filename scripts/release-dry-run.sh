#!/usr/bin/env bash
# Usage: release-dry-run.sh [OUT_DIR]
# Local run of the release scripts against a one-triple build of smith (host
# triple only): manifest, SBOM, a throwaway minisign signature, then
# verify-release.sh. Mirrors the dry-run path of .github/workflows/release.yml
# without cosign keyless signing (needs CI's OIDC token), so cosign is SKIPped
# and the Homebrew formula (needs all four triples) is not generated.
# Nothing here reads a real key; the throwaway key lives in a temp dir.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$root/target/release-dry-run}"
for t in cargo jq minisign; do
  command -v "$t" >/dev/null 2>&1 || { echo "SKIP release-dry-run: $t is not installed (not a pass)"; exit 0; }
done
triple="$(rustc -vV | awk '/^host:/{print $2}')"
case "$triple" in
  aarch64-apple-darwin|x86_64-apple-darwin|aarch64-unknown-linux-gnu|x86_64-unknown-linux-gnu) ;;
  *) echo "release-dry-run: unsupported host triple $triple" >&2; exit 1 ;;
esac
version="$(awk '/^\[workspace\.package\]/{f=1;next} /^\[/{f=0} f && /^version *=/{gsub(/[" ]/,"",$3); print $3; exit}' "$root/Cargo.toml")"
[ -n "$version" ] || { echo "release-dry-run: no workspace version" >&2; exit 1; }

(cd "$root" && LOCKSMITH_CHANNEL=stable cargo build --release --locked -p smith-cli)
rm -rf "$OUT" && mkdir -p "$OUT"
cp "$root/target/release/smith" "$OUT/smith-$triple"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# SBOM: syft when present (as in CI), else a minimal CycloneDX document from cargo metadata.
if command -v syft >/dev/null 2>&1; then
  (cd "$root" && syft scan dir:. -o "cyclonedx-json=$tmp/sbom.cdx.json")
else
  (cd "$root" && cargo metadata --locked --format-version 1 --filter-platform "$triple") | jq '{
    bomFormat: "CycloneDX", specVersion: "1.5", version: 1,
    components: [.packages[] | {type: "library", name: .name, version: .version, purl: ("pkg:cargo/" + .name + "@" + .version)}]}' > "$tmp/sbom.cdx.json"
fi

"$root/scripts/make-manifest.sh" "$version" "$OUT" --allow-partial --sbom "$tmp/sbom.cdx.json"

umask 077
minisign -G -W -p "$tmp/pub" -s "$tmp/key" >/dev/null
sed -n 2p "$tmp/pub" > "$OUT/dry-run-pubkey.txt"
minisign -S -s "$tmp/key" -m "$OUT/manifest.json" -x "$OUT/manifest.json.minisig" </dev/null >/dev/null

"$root/scripts/verify-release.sh" "$OUT" --pubkey "$OUT/dry-run-pubkey.txt" --skip-cosign
echo "release-dry-run: ok ($OUT)"
