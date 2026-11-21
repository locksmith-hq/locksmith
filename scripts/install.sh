#!/usr/bin/env bash
# Installs the smith CLI from the public locksmith-hq/locksmith GitHub Releases.
# Usage: install.sh [--version X.Y.Z] [--dir DIR]
# Needs curl, minisign and jq (or python3). It verifies the minisign signature of
# manifest.json and the SHA-256 of the binary before installing, and stops if it
# cannot verify. It installs only the binary and reads no credential files.
set -euo pipefail

REPO="locksmith-hq/locksmith"
# Matches crates/ls-update/update-pubkey.txt (single base64 line).
PUBKEY="RWThYqgH41ct5yy121QaufJSN/s6I+bPEH9IDVeh3svY1vMkBNYBfUYs"

die() { echo "install: $*" >&2; exit 1; }

VERSION="" BIN_DIR="${LOCKSMITH_BIN_DIR:-$HOME/.local/bin}"
while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="${2#v}"; shift 2 ;;
    --dir) [ $# -ge 2 ] || die "--dir needs a value"; BIN_DIR="$2"; shift 2 ;;
    -h|--help) sed -n 2,6p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
if [ -n "$VERSION" ]; then
  [[ "$VERSION" =~ ^[0-9A-Za-z.+-]+$ ]] || die "invalid version: $VERSION"
fi

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) TRIPLE=aarch64-apple-darwin ;;
  Darwin-x86_64) TRIPLE=x86_64-apple-darwin ;;
  Linux-x86_64) TRIPLE=x86_64-unknown-linux-gnu ;;
  Linux-aarch64|Linux-arm64) TRIPLE=aarch64-unknown-linux-gnu ;;
  *) die "unsupported platform: $(uname -s) $(uname -m)" ;;
esac

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v minisign >/dev/null 2>&1 \
  || die "minisign is required to verify the download and is not installed (brew install minisign, or your package manager); nothing was installed"

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "sha256sum or shasum is required"
fi
if command -v jq >/dev/null 2>&1; then
  HAVE_JQ=1
elif command -v python3 >/dev/null 2>&1; then
  HAVE_JQ=0
else
  die "jq or python3 is required to read the manifest"
fi

# LOCKSMITH_RELEASE_URL points the installer at another release directory (used by the tests).
if [ -n "${LOCKSMITH_RELEASE_URL:-}" ]; then
  BASE="${LOCKSMITH_RELEASE_URL%/}"; PROTO='=https,file'
elif [ -n "$VERSION" ]; then
  BASE="https://github.com/$REPO/releases/download/v$VERSION"; PROTO='=https'
else
  BASE="https://github.com/$REPO/releases/latest/download"; PROTO='=https'
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# -q ignores any curl config file, and no credential option is used.
fetch() { curl -q -fsSL --proto "$PROTO" --proto-redir "$PROTO" -o "$TMP/$1" "$BASE/$1" || die "download failed: $1"; }
fetch manifest.json
fetch manifest.json.minisig

minisign -V -P "$PUBKEY" -m "$TMP/manifest.json" -x "$TMP/manifest.json.minisig" >/dev/null 2>&1 \
  || die "manifest signature check failed; nothing was installed"
echo "manifest signature OK"

if [ "$HAVE_JQ" = 1 ]; then
  ROW="$(jq -r --arg t "$TRIPLE" '.targets[$t] | select(. != null) | "\(.name) \(.sha256)"' "$TMP/manifest.json")" || ROW=""
else
  ROW="$(python3 -c 'import json,sys; t=json.load(open(sys.argv[1]))["targets"].get(sys.argv[2]); print("%s %s" % (t["name"], t["sha256"]) if t else "")' "$TMP/manifest.json" "$TRIPLE")" || ROW=""
fi
[ -n "$ROW" ] || die "manifest has no build for $TRIPLE"
read -r NAME EXPECTED <<< "$ROW"
[ "$NAME" = "smith-$TRIPLE" ] || die "manifest names unexpected asset: $NAME"

fetch "$NAME"
ACTUAL="$(sha256 "$TMP/$NAME")"
[ "$ACTUAL" = "$EXPECTED" ] || die "sha256 mismatch for $NAME (expected $EXPECTED, got $ACTUAL); nothing was installed"
echo "sha256 OK for $NAME"

mkdir -p "$BIN_DIR"
install -m 755 "$TMP/$NAME" "$BIN_DIR/smith"
echo "installed $BIN_DIR/smith"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "note: $BIN_DIR is not on PATH" ;;
esac

cat <<'MSG'

Next steps:
  smith --version
  smith doctor
Update later with: smith update
MSG
