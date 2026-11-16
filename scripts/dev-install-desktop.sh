#!/usr/bin/env bash
# Local dev install (macOS): build smith, locksmithd, locksmith-mcp and the desktop app, put them all in one
# Locksmith.app (the daemon attests locksmith-desktop only when it sits next to locksmithd),
# and link smith into ~/.local/bin. Debug builds; not signed for distribution.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dest="${LOCKSMITH_APP_DIR:-$HOME/Applications}/Locksmith.app"
bin="${LOCKSMITH_BIN_DIR:-$HOME/.local/bin}"

[[ "$(uname)" == Darwin ]] || { echo "macOS only; on Linux run the binaries from target/debug" >&2; exit 1; }

cargo build --manifest-path "$root/Cargo.toml" -p smith-cli -p locksmithd -p locksmith-mcp
(cd "$root/apps/desktop" && npm exec -- tauri build --debug --bundles app --config '{"bundle":{"active":true}}')

# A daemon started from the old bundle keeps the old binaries pinned; stop it first.
pkill -f "$dest/Contents/MacOS/locksmithd" || true

rm -rf "$dest"
mkdir -p "$(dirname "$dest")" "$bin"
ditto "$root/apps/desktop/src-tauri/target/debug/bundle/macos/Locksmith.app" "$dest"
cp "$root/target/debug/smith" "$root/target/debug/locksmithd" "$root/target/debug/locksmith-mcp" "$dest/Contents/MacOS/"
# Adding binaries breaks the bundle seal; re-sign ad hoc so macOS launches it.
codesign --force --deep --sign - "$dest" >/dev/null
ln -sf "$dest/Contents/MacOS/smith" "$bin/smith"
ln -sf "$dest/Contents/MacOS/locksmith-mcp" "$bin/locksmith-mcp"

echo "Installed $dest"
echo "smith -> $bin/smith, locksmith-mcp -> $bin/locksmith-mcp"
