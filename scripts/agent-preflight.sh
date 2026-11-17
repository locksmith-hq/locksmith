#!/usr/bin/env bash
# Preflight for scheduled agents (docs/agents/common.md): find environment problems in seconds
# instead of minutes into a run. Fixes what is safe (start docker, install just); reports the rest.
# Prints one line per check: OK / FIXED / FAIL <hint>. Exit 0 unless a required check FAILs.
set -uo pipefail
fail=0
say() { printf '%-6s %-14s %s\n' "$1" "$2" "${3:-}"; }
sudo_() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo -n "$@"; fi; }

# docker daemon (needed for `just up` once F0 exists)
if ! command -v docker >/dev/null; then say FAIL docker "not installed"; fail=1
elif docker info >/dev/null 2>&1; then say OK docker
else
  # Docker Hub rate-limits anonymous pulls (429s on 2026-11-16 and -17), so pull through
  # Google's public Docker Hub mirror; dockerd falls back to Docker Hub. Never overwrite a config.
  [ -e /etc/docker/daemon.json ] || { sudo_ mkdir -p /etc/docker && echo '{"registry-mirrors":["https://mirror.gcr.io"]}' | sudo_ tee /etc/docker/daemon.json >/dev/null; }
  (sudo_ service docker start || (sudo_ dockerd >/tmp/dockerd.log 2>&1 &)) >/dev/null 2>&1
  for _ in $(seq 1 20); do docker info >/dev/null 2>&1 && break; sleep 1; done
  if docker info >/dev/null 2>&1; then say FIXED docker "daemon started"; else say FAIL docker "daemon down, see /tmp/dockerd.log"; fail=1; fi
fi

# just
if command -v just >/dev/null; then say OK just
elif (sudo_ apt-get install -y -q just >/dev/null 2>&1 || cargo install --locked just >/dev/null 2>&1) && command -v just >/dev/null; then say FIXED just "installed"
else say FAIL just "install failed"; fail=1; fi

# rust toolchain pinned by rust-toolchain.toml
if cargo --version >/dev/null 2>&1; then say OK cargo "$(cargo --version | cut -d' ' -f2)"; else say FAIL cargo "toolchain missing"; fail=1; fi
if cargo nextest --version >/dev/null 2>&1; then say OK nextest; else say WARN nextest "missing: cargo install --locked cargo-nextest (run in background)"; fi

# Pinned CI tools missing from the cloud VM (cargo install took 114 s; guessing gitleaks
# fingerprints without the binary cost 3 hygiene re-pushes). Prebuilt, sha256-checked; WARN only.
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

# node / openspec
if command -v node >/dev/null; then say OK node "$(node --version)"; else say FAIL node "missing"; fail=1; fi
if command -v openspec >/dev/null; then say OK openspec; else say WARN openspec "missing: npm i -g @fission-ai/openspec"; fi

# npm deps (test-web needs them; npm ci takes minutes, so run it in the background)
if [ -d node_modules ]; then say OK node_modules; else say WARN node_modules "missing: run 'npm ci' in the background before just ci"; fi

# container registries (ghcr.io returned 403 in the Claude cloud sandbox on 2026-11-16)
for r in https://registry-1.docker.io/v2/ https://ghcr.io/v2/; do
  code=$(curl -s -m 8 -o /dev/null -w '%{http_code}' "$r")
  case "$code" in 200|401) say OK registry "$r" ;; *) say WARN registry "$r -> HTTP $code (use a Docker Hub image instead)" ;; esac
done

# disk (cargo target dirs fill 30 GB VMs fast)
avail=$(df -Pk . | awk 'NR==2 {print int($4/1048576)}')
if [ "${avail:-0}" -ge 5 ]; then say OK disk "${avail} GB free"; else say WARN disk "${avail} GB free: run cargo clean -p <crate> or remove target/debug/incremental"; fi

# network: registries the build needs (allowlist problems show up here, not 10 min into a build)
for h in https://index.crates.io/config.json https://registry.npmjs.org/ https://api.github.com/; do
  if curl -fsS -m 8 -o /dev/null "$h"; then say OK net "$h"; else say WARN net "$h unreachable (environment allowlist?)"; fi
done

# GitHub auth through the cloud proxy (REST)
if gh api rate_limit >/dev/null 2>&1; then say OK gh-api; else say WARN gh-api "gh api failed"; fi

exit "$fail"
