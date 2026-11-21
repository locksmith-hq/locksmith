#!/usr/bin/env bash
# Tests scripts/verify-release.sh with a throwaway minisign key and a stub cosign.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if ! command -v minisign >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
  echo "SKIP verify-release.test: minisign and jq are required (not a pass)"; exit 0
fi
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
T="aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu"

minisign -G -W -p "$tmp/pub" -s "$tmp/sec" >/dev/null 2>&1
pub="$(sed -n 2p "$tmp/pub")"; echo "$pub" > "$tmp/pubkey.txt"

mkdir "$tmp/bin"
cat > "$tmp/bin/cosign" <<'STUB'
#!/usr/bin/env bash
# Test identity: accepts only the identity regexp given by COSIGN_STUB_WANT.
id=""; while [ $# -gt 0 ]; do [ "$1" = "--certificate-identity-regexp" ] && id="$2"; shift; done
[ "$id" = "${COSIGN_STUB_WANT:-}" ]
STUB
chmod +x "$tmp/bin/cosign"

mk() {
  d="$1"; rm -rf "$d"; mkdir -p "$d"
  for t in $T; do echo "bin $t" > "$d/smith-$t"; done
  echo '{"bomFormat":"CycloneDX","specVersion":"1.5"}' > "$tmp/sbom.json"
  "$here/make-manifest.sh" 1.2.3 "$d" --sbom "$tmp/sbom.json" >/dev/null
  minisign -S -s "$tmp/sec" -m "$d/manifest.json" -x "$d/manifest.json.minisig" </dev/null >/dev/null 2>&1
  echo bundle > "$d/manifest.json.bundle"
}
run() { PATH="$tmp/bin:$PATH" COSIGN_STUB_WANT='^want$' "$here/verify-release.sh" "$@"; }

mk "$tmp/good"
out="$(run "$tmp/good" --pubkey "$tmp/pubkey.txt" --identity-regexp '^want$')" || fail "good release rejected: $out"
[ "$(grep -c '^OK' <<< "$out")" -eq 7 ] || fail "expected 7 OK lines: $out"

# tampered asset byte
mk "$tmp/t1"; printf 'X' >> "$tmp/t1/smith-x86_64-apple-darwin"
if run "$tmp/t1" --pubkey "$tmp/pubkey.txt" --identity-regexp '^want$' >/dev/null; then fail "tampered asset accepted"; fi

# tampered manifest (signature must fail)
mk "$tmp/t2"; sed -i 's/1.2.3/9.9.9/' "$tmp/t2/manifest.json"
if run "$tmp/t2" --pubkey "$tmp/pubkey.txt" --identity-regexp '^want$' >/dev/null; then fail "tampered manifest accepted"; fi

# wrong key
minisign -G -W -p "$tmp/pub2" -s "$tmp/sec2" >/dev/null 2>&1; sed -n 2p "$tmp/pub2" > "$tmp/pubkey2.txt"
if run "$tmp/good" --pubkey "$tmp/pubkey2.txt" --identity-regexp '^want$' >/dev/null; then fail "wrong key accepted"; fi

# wrong cosign identity
if run "$tmp/good" --pubkey "$tmp/pubkey.txt" --identity-regexp '^other$' >/dev/null; then fail "wrong identity accepted"; fi

# missing SBOM, missing asset
mk "$tmp/t3"; rm "$tmp/t3/sbom.cdx.json"
if run "$tmp/t3" --pubkey "$tmp/pubkey.txt" --identity-regexp '^want$' >/dev/null; then fail "missing SBOM accepted"; fi
mk "$tmp/t4"; rm "$tmp/t4/smith-aarch64-apple-darwin"
if run "$tmp/t4" --pubkey "$tmp/pubkey.txt" --identity-regexp '^want$' >/dev/null; then fail "missing asset accepted"; fi

# no cosign: fails unless --skip-cosign (and that prints SKIP)
if PATH="/usr/bin:/bin" "$here/verify-release.sh" "$tmp/good" --pubkey "$tmp/pubkey.txt" >/dev/null 2>&1 && ! command -v cosign >/dev/null; then fail "missing cosign accepted"; fi
out="$("$here/verify-release.sh" "$tmp/good" --pubkey "$tmp/pubkey.txt" --skip-cosign)" || fail "--skip-cosign failed: $out"
grep -q '^SKIP' <<< "$out" || fail "no SKIP line"

echo "verify-release.test: ok"
