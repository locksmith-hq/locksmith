#!/usr/bin/env bash
# Headless desktop smoke test: launch the built desktop binary with --health and wait for
# locksmithd to answer a ping. Exit 0 when healthy, non-zero when the daemon is down or the
# binary is missing. Usage: scripts/desktop-smoke.sh [wait-seconds]
# Env: LS_DESKTOP_BIN overrides the binary path (default: the debug build).
set -euo pipefail
cd "$(dirname "$0")/.."
wait_secs="${1:-10}"
bin="${LS_DESKTOP_BIN:-}"
if [ -z "$bin" ]; then
  for c in apps/desktop/src-tauri/target/debug/locksmith-desktop \
           apps/desktop/src-tauri/target/debug/locksmith-desktop.exe; do
    [ -x "$c" ] && bin="$c" && break
  done
fi
if [ -z "$bin" ] || [ ! -x "$bin" ]; then
  echo "desktop-smoke: desktop binary not found (run 'just apps-build' first)" >&2
  exit 2
fi
exec "$bin" --health "$wait_secs"
