#!/usr/bin/env bash
# T6: invite and membership abuse. Runs the `members_abuse` cargo test, which drives the real
# handlers against a throwaway Postgres (testcontainers): another org's owner naming this org
# gets a uniform 404 on every members and invites route, guessed, near-miss, replayed, revoked
# and other-email invite tokens are all the same 404 (a wrong email does not burn the invite),
# and the plaintext token appears in no invite row, ledger row or response transcript. The
# test writes those to ARTIFACT_DIR and the shared oracle scans them. Exits 77 without Docker.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
: "${CANARY_FILE:?CANARY_FILE is required}" "${ARTIFACT_DIR:?ARTIFACT_DIR is required}"

command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 ||
  { echo "skip: Docker is not available (the members tests start postgres:18)"; exit 77; }

# run.sh replaces HOME with a throwaway directory; keep rustup, cargo and Docker config.
real_home="$(eval echo "~$(id -un)")"
export RUSTUP_HOME="${RUSTUP_HOME:-$real_home/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$real_home/.cargo}"
export DOCKER_CONFIG="${DOCKER_CONFIG:-$real_home/.docker}"
export PATH="/opt/homebrew/opt/rustup/bin:$CARGO_HOME/bin:$PATH"

export MEMBERS_ABUSE_ARTIFACT_DIR="$ARTIFACT_DIR"
cd "$root"
cargo test -p ls-control-plane --test members members_abuse -- --test-threads=1 \
  >"$ARTIFACT_DIR/cargo-test.log" 2>&1 || { tail -n 60 "$ARTIFACT_DIR/cargo-test.log" >&2; exit 1; }
for f in members-abuse.transcript members-abuse.invites members-abuse.ledger; do
  [[ -s "$ARTIFACT_DIR/$f" ]] || { echo "the test wrote no $f" >&2; exit 1; }
done
echo "ok: members_abuse test passed"
