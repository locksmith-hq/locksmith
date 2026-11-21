#!/usr/bin/env bash
# `just sdk-smoke`: sign in as the seeded Keycloak user (as scripts/auth-e2e.py does), run the SDK
# smoke test, then run `just leak-scan` over its output. Needs `just up` and `just api`.
# The token goes through a 0600 temp file that is removed on exit; it is never printed.
set -euo pipefail
cd "$(dirname "$0")/.."
f=$(mktemp); out=$(mktemp); trap 'rm -f "$f" "$out"' EXIT; chmod 600 "$f"
python3 -I - "$f" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("auth_e2e", "scripts/auth-e2e.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
tok, _ = m.sign_in(*m.SEEDED_OK)
if not tok:
    sys.exit("sdk-smoke: sign-in as the seeded user failed (is `just up` running?)")
open(sys.argv[1], "w").write(tok)
PY
LOCKSMITH_SMOKE_TOKEN_FILE="$f" npx vitest run --root tests/e2e/sdk-smoke 2>&1 | tee "$out"
[ -f "${LOCKSMITH_CANARIES:-infra/compose/.canaries}" ] || just canary new >/dev/null
just leak-scan --transcript "$out"
