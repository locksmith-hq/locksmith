#!/usr/bin/env bash
# Installs the smith CLI from the private tomer555/locksmith GitHub Releases.
# Requires gh (authenticated with access to the repo).
set -euo pipefail

REPO="tomer555/locksmith"
# Matches crates/ls-update/update-pubkey.txt (single base64 line).
PUBKEY="RWThYqgH41ct5yy121QaufJSN/s6I+bPEH9IDVeh3svY1vMkBNYBfUYs"

die() { echo "install: $*" >&2; exit 1; }

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) TRIPLE=aarch64-apple-darwin ;;
  Darwin-x86_64) TRIPLE=x86_64-apple-darwin ;;
  Linux-x86_64) TRIPLE=x86_64-unknown-linux-gnu ;;
  Linux-aarch64) TRIPLE=aarch64-unknown-linux-gnu ;;
  *) die "unsupported platform: $(uname -s) $(uname -m)" ;;
esac

command -v gh >/dev/null 2>&1 || die "gh is required: https://cli.github.com"
gh auth status >/dev/null 2>&1 || die "gh is not authenticated; run 'gh auth login'"

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
else
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

gh release download --repo "$REPO" \
  --pattern "smith-$TRIPLE" --pattern manifest.json --pattern manifest.json.minisig \
  --dir "$TMP"

if command -v minisign >/dev/null 2>&1; then
  minisign -V -P "$PUBKEY" -m "$TMP/manifest.json" -x "$TMP/manifest.json.minisig" >/dev/null \
    || die "manifest signature check failed"
  echo "manifest signature OK"
else
  echo "warning: minisign not installed, skipping manifest signature check" >&2
fi

# Read the expected name and sha256 for this triple from the manifest.
if command -v jq >/dev/null 2>&1; then
  read -r NAME EXPECTED < <(jq -r --arg t "$TRIPLE" '.targets[$t] | "\(.name) \(.sha256)"' "$TMP/manifest.json")
else
  read -r NAME EXPECTED < <(python3 -c 'import json,sys; t=json.load(open(sys.argv[1]))["targets"][sys.argv[2]]; print(t["name"], t["sha256"])' "$TMP/manifest.json" "$TRIPLE")
fi
[ "$NAME" = "smith-$TRIPLE" ] || die "manifest names unexpected asset: $NAME"

ACTUAL="$(sha256 "$TMP/smith-$TRIPLE")"
[ "$ACTUAL" = "$EXPECTED" ] || die "sha256 mismatch for $NAME (expected $EXPECTED, got $ACTUAL)"
echo "sha256 OK for $NAME"

BIN_DIR="${LOCKSMITH_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"
install -m 755 "$TMP/smith-$TRIPLE" "$BIN_DIR/smith"
echo "installed $BIN_DIR/smith"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "note: $BIN_DIR is not on PATH" ;;
esac

cat <<EOF

Next steps:
  smith --version
  smith doctor
Updates come from the private release; run:
  GH_TOKEN=\$(gh auth token) smith self update
EOF
