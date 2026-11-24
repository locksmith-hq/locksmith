#!/usr/bin/env bash
# Prebuilt, sha256-checked CI tools for agent VMs: cargo install took 114 s, and guessing gitleaks
# fingerprints without the binary cost 3 hygiene re-pushes. Called by cloud-setup.sh (cached in
# the VM image) and by claude-ai-crew's agent-preflight.sh (fallback). Prints OK / FIXED / WARN per tool; exit 0.
set -uo pipefail
say() { printf '%-6s %-14s %s\n' "$1" "$2" "${3:-}"; }
tool() { # <name> <url> <sha256> <path-in-tarball>
  { command -v "$1" || [ -x "$HOME/.cargo/bin/$1" ]; } >/dev/null && { say OK "$1"; return; }
  [ "$(uname -sm)" = "Linux x86_64" ] || { say WARN "$1" "missing (no prebuilt for $(uname -sm))"; return; }
  local d; d=$(mktemp -d)
  if curl -fsSL -m 60 -o "$d/t.tgz" "$2" && echo "$3  $d/t.tgz" | sha256sum -c --quiet - \
     && tar xzf "$d/t.tgz" -C "$d" && mkdir -p "$HOME/.cargo/bin" && install -m 755 "$d/$4" "$HOME/.cargo/bin/$1"
  then say FIXED "$1" "installed"; else say WARN "$1" "install failed"; fi
  rm -rf "$d"
}
tool gitleaks https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
  551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb gitleaks  # same version as ci.yml
tool cargo-deny https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz \
  9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f cargo-deny-0.20.2-x86_64-unknown-linux-musl/cargo-deny
exit 0
