#!/usr/bin/env bash
# Prebuilt, sha256-checked CI tools for agent VMs: cargo install took 114 s, and guessing gitleaks
# fingerprints without the binary cost 3 hygiene re-pushes. Called by cloud-setup.sh (cached in
# the VM image) and by agent-preflight.sh (fallback). Prints OK / FIXED / WARN per tool; exit 0.
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
# Packaging tools (p2-packaging): pins and dates in docs/research/packaging.md. Helm is not here: get.helm.sh
# returns 403 through the agent proxy, so `just helm-test` skips with a message when helm is absent.
bin() { # <name> <url> <sha256>  (single static binary, no tarball)
  { command -v "$1" || [ -x "$HOME/.cargo/bin/$1" ]; } >/dev/null && { say OK "$1"; return; }
  [ "$(uname -sm)" = "Linux x86_64" ] || { say WARN "$1" "missing (no prebuilt for $(uname -sm))"; return; }
  local d; d=$(mktemp -d)
  if curl -fsSL -m 90 -o "$d/b" "$2" && echo "$3  $d/b" | sha256sum -c --quiet - \
     && mkdir -p "$HOME/.cargo/bin" && install -m 755 "$d/b" "$HOME/.cargo/bin/$1"
  then say FIXED "$1" "installed"; else say WARN "$1" "install failed"; fi
  rm -rf "$d"
}
bin cosign https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64 \
  424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
bin kind https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64 \
  aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
tool kubeconform https://github.com/yannh/kubeconform/releases/download/v0.8.0/kubeconform-linux-amd64.tar.gz \
  9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883 kubeconform
tool syft https://github.com/anchore/syft/releases/download/v1.57.2/syft_1.57.2_linux_amd64.tar.gz \
  ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b syft
exit 0
