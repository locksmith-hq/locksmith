#!/usr/bin/env bash
# Setup script for the Claude Code cloud environment "locksmith-dev" (paste into the environment's
# setup script field). Runs as root on Ubuntu 24.04 before Claude starts; result is cached if it
# finishes in about 5 minutes, so keep slow, rarely-changing installs here. See docs/cloud-dev.md.
set -uo pipefail

apt-get update -q && apt-get install -y -q libssl-dev pkg-config just || true

# Rust toolchain pinned by rust-toolchain.toml (rustup downloads it on first cargo call; do it now).
command -v rustup >/dev/null || curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install 1.100.0 --profile minimal -c rustfmt -c clippy || true
cargo install --locked cargo-nextest || true

npm i -g @fission-ai/openspec || true
[ -f package-lock.json ] && npm ci --no-audit --no-fund || true

# Pre-pull the F0 stack images so sessions start fast (images are cached; containers are not).
if [ -f infra/compose/compose.yaml ]; then
  (service docker start || dockerd >/dev/null 2>&1 &) ; sleep 3
  docker compose -f infra/compose/compose.yaml pull || true
fi
exit 0
