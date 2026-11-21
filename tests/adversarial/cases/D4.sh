#!/usr/bin/env bash
# D4: workload token exchange (POST /v1/workload-tokens) abuse. Runs the `workload_abuse` cargo
# tests, which drive the real handler against a throwaway Postgres (testcontainers) and wiremock
# stub issuers: a forged `iss` at an attacker host makes no outbound call, `jku`/`x5u`/`jwk`
# headers are ignored, a token for another audience, a replayed or racing `jti` and another org's
# policy handle are all the same 401. The canary rides in the external token's claims; the tests
# write the captured logs (with spans), the audit ledger and a dump of every table to
# ARTIFACT_DIR, and the shared oracle scans them. Exits 77 when Docker is not available.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
: "${CANARY_FILE:?CANARY_FILE is required}" "${ARTIFACT_DIR:?ARTIFACT_DIR is required}"

command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 ||
  { echo "skip: Docker is not available (the exchange tests start postgres:18)"; exit 77; }

# run.sh replaces HOME with a throwaway directory; keep rustup, cargo and Docker config.
real_home="$(eval echo "~$(id -un)")"
export RUSTUP_HOME="${RUSTUP_HOME:-$real_home/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$real_home/.cargo}"
export DOCKER_CONFIG="${DOCKER_CONFIG:-$real_home/.docker}"
export PATH="/opt/homebrew/opt/rustup/bin:$CARGO_HOME/bin:$PATH"

export ADVERSARIAL_CANARY_FILE="$CANARY_FILE"
export WORKLOAD_ABUSE_ARTIFACT_DIR="$ARTIFACT_DIR"
cd "$root"
if command -v cargo-nextest >/dev/null 2>&1; then
  cargo nextest run -p ls-control-plane workload_abuse >"$ARTIFACT_DIR/cargo-test.log" 2>&1
else
  cargo test -p ls-control-plane --test workload_exchange workload_abuse >"$ARTIFACT_DIR/cargo-test.log" 2>&1
fi
for f in canary.logs canary.ledger canary.rows; do
  [[ -s "$ARTIFACT_DIR/$f" ]] || { echo "the tests wrote no $f" >&2; exit 1; }
done
echo "ok: workload_abuse tests passed"
