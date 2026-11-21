#!/usr/bin/env bash
# Tests scripts/install.sh against a local release directory (file://) with a throwaway
# minisign key. Needs minisign, jq and curl; prints SKIP, never a pass, when one is missing.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
for t in minisign jq curl; do
  command -v "$t" >/dev/null 2>&1 || { echo "SKIP install.test: $t is required (not a pass)"; exit 0; }
done
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) T=aarch64-apple-darwin ;;
  Darwin-x86_64) T=x86_64-apple-darwin ;;
  Linux-x86_64) T=x86_64-unknown-linux-gnu ;;
  Linux-aarch64|Linux-arm64) T=aarch64-unknown-linux-gnu ;;
  *) echo "SKIP install.test: unsupported host"; exit 0 ;;
esac

minisign -G -W -p "$tmp/pub" -s "$tmp/sec" >/dev/null 2>&1
minisign -G -W -p "$tmp/pub2" -s "$tmp/sec2" >/dev/null 2>&1
# The installer pins its key; the test swaps in the throwaway key in a copy.
inst="$tmp/install.sh"
sed "s|^PUBKEY=.*|PUBKEY=\"$(sed -n 2p "$tmp/pub")\"|" "$here/install.sh" > "$inst"
grep -q "$(sed -n 2p "$tmp/pub")" "$inst" || fail "could not set the test key"

mk() { # mk DIR [signing-secret]
  d="$1"; sec="${2:-$tmp/sec}"; rm -rf "$d"; mkdir -p "$d"
  for t in aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu; do
    printf '#!/bin/sh\necho smith-test %s\n' "$t" > "$d/smith-$t"
  done
  "$here/make-manifest.sh" 1.2.3 "$d" >/dev/null
  minisign -S -s "$sec" -m "$d/manifest.json" -x "$d/manifest.json.minisig" </dev/null >/dev/null 2>&1
}

# A HOME holding canary credentials; the installer must not read or print them.
home="$tmp/home"; mkdir -p "$home/.aws" "$home/.config/gh"
CANARY="canary-secret-$RANDOM$RANDOM"
printf 'machine github.com login x password %s\n' "$CANARY" > "$home/.netrc"
printf 'aws_secret_access_key=%s\n' "$CANARY" > "$home/.aws/credentials"
printf 'oauth_token: %s\n' "$CANARY" > "$home/.config/gh/hosts.yml"

run() { # run RELEASE_DIR [args...]; output in $tmp/out
  rel="$1"; shift
  env -i PATH="$PATH" HOME="$home" GH_TOKEN="$CANARY" GITHUB_TOKEN="$CANARY" AWS_SECRET_ACCESS_KEY="$CANARY" \
    LOCKSMITH_RELEASE_URL="file://$rel" bash "$inst" "$@" > "$tmp/out" 2>&1
}
no_leak() { grep -q "$CANARY" "$tmp/out" && fail "credential value printed: $(cat "$tmp/out")" || true; }

# good install, with --dir
mk "$tmp/rel"; bin="$tmp/bin1"
run "$tmp/rel" --dir "$bin" || fail "good install failed: $(cat "$tmp/out")"
no_leak
[ -x "$bin/smith" ] || fail "binary not installed"
[ "$("$bin/smith")" = "smith-test $T" ] || fail "wrong binary installed"
[ "$(ls "$bin")" = "smith" ] || fail "installed more than the binary"
grep -q "sha256 OK" "$tmp/out" || fail "no sha256 line"

# --version is accepted and validated
run "$tmp/rel" --version v1.2.3 --dir "$tmp/bin1b" || fail "--version install failed: $(cat "$tmp/out")"
if run "$tmp/rel" --version '1;rm' --dir "$tmp/bin1c"; then fail "bad version accepted"; fi
[ ! -e "$tmp/bin1c" ] || fail "installed on bad version"

# bad signature: manifest signed by another key
mk "$tmp/badsig" "$tmp/sec2"; bin="$tmp/bin2"
if run "$tmp/badsig" --dir "$bin"; then fail "bad signature accepted"; fi
grep -q "signature check failed" "$tmp/out" || fail "no signature message: $(cat "$tmp/out")"
[ ! -e "$bin/smith" ] || fail "installed despite bad signature"

# bad hash: binary changed after signing
mk "$tmp/badhash"; echo tampered >> "$tmp/badhash/smith-$T"; bin="$tmp/bin3"
if run "$tmp/badhash" --dir "$bin"; then fail "bad hash accepted"; fi
grep -q "sha256 mismatch" "$tmp/out" || fail "no hash message: $(cat "$tmp/out")"
[ ! -e "$bin/smith" ] || fail "installed despite bad hash"

# missing verifier: PATH without minisign
mkdir "$tmp/nominisign"
for t in bash sh env curl jq uname mktemp rm mkdir install awk sed grep cat sha256sum shasum python3 dirname head tr; do
  p="$(command -v "$t" 2>/dev/null || true)"; [ -n "$p" ] && ln -s "$p" "$tmp/nominisign/$t"
done
bin="$tmp/bin4"
if env -i PATH="$tmp/nominisign" HOME="$home" LOCKSMITH_RELEASE_URL="file://$tmp/rel" "$tmp/nominisign/bash" "$inst" --dir "$bin" > "$tmp/out" 2>&1; then fail "installed without a verifier"; fi
grep -q "minisign is required" "$tmp/out" || fail "no clear stop for missing minisign: $(cat "$tmp/out")"
[ ! -e "$bin/smith" ] || fail "installed without a verifier"

# unsupported platform: fake uname
mkdir "$tmp/fakeuname"
printf '#!/bin/sh\ncase "$1" in -s) echo Plan9;; -m) echo mips;; *) echo Plan9;; esac\n' > "$tmp/fakeuname/uname"; chmod +x "$tmp/fakeuname/uname"
bin="$tmp/bin5"
if env -i PATH="$tmp/fakeuname:$PATH" HOME="$home" LOCKSMITH_RELEASE_URL="file://$tmp/rel" bash "$inst" --dir "$bin" > "$tmp/out" 2>&1; then fail "unsupported platform accepted"; fi
grep -q "unsupported platform" "$tmp/out" || fail "no platform message"

# the script itself names no credential file and does not use gh or -n for curl
if grep -nE 'netrc|\.aws|gh auth|hosts\.yml|GH_TOKEN|GITHUB_TOKEN|credentials|\bgh (api|release)' "$here/install.sh"; then fail "install.sh references credentials or gh"; fi

echo "install.test: OK"
