#!/usr/bin/env bash
# Self-test for the owner-replies.sh classifier (no GitHub calls).
set -euo pipefail
s="$(dirname "$0")/owner-replies.sh"
t() { got=$(printf '%s' "$2" | bash "$s" -); [ "$got" = "$1" ] || { echo "owner-replies: '$2' gave $got, want $1"; exit 1; }; }
for b in approved Approved. "  LGTM! " yes ok "go ahead" 👍; do t approval "$b"; done
for b in "approved, but use postgres" "no, do X instead" "why?" ""; do t demand "$b"; done
echo "owner-replies: OK"
