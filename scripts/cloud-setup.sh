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
# Prebuilt nextest from GitHub releases (allowlisted): compiling it took minutes and broke the cache budget.
NEXTEST=cargo-nextest-0.9.152-x86_64-unknown-linux-gnu
( cd /tmp && curl -fsSL --remote-name-all "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.152/$NEXTEST".{tar.gz,sha256} \
  && sha256sum -c "$NEXTEST.sha256" && tar xzf "$NEXTEST.tar.gz" -C "$HOME/.cargo/bin" ) || true

# gitleaks and cargo-deny: preflight installed them in every run (60-120 s of logged friction each).
bash scripts/ci-tools.sh || true

npm i -g @fission-ai/openspec || true
[ -f package-lock.json ] && npm ci --no-audit --no-fund || true

# No Docker here: starting dockerd and pulling ~2 GB of images blew the 5-minute cache budget
# (lead run 2026-11-17 hung in setup). `just up` pulls images on demand.
exit 0
