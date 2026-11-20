#!/usr/bin/env bash
# G10: Postgres relay (D3 task 4.3): the gateway's pgwire listener (LOCKSMITH_GATEWAY_PG_LISTEN,
# TLS) in front of the stack's Postgres. The canary is the password of a throwaway role
# (`g10_<pid>`, created and dropped by the case as the operator); the secret is bound as a
# `[[pg]]` binding (tls = disable to the loopback stack, which the gateway allows only with
# allow_private_hosts). The agent is `psql` with its token as the password, over TLS, with a
# hostile startup (`user=postgres`). Probes:
#   - error and notice echo: a DO block raises the canary in `RAISE NOTICE` and `RAISE EXCEPTION`
#     (message, DETAIL and HINT), as if the server echoed the credential: the client sees the
#     `[REDACTED` marker (redaction is on) and never the canary;
#   - options role switch: `options=-c role=postgres -c session_authorization=postgres` and a
#     `replication=database` startup parameter leave the session on the bound role
#     (current_user = session_user = the role, role = none, no walsender);
#   - cancel with a guessed key: while a `pg_sleep` runs, CancelRequests for the upstream's real
#     backend pid (learned with `pg_backend_pid()`), pid/key pairs near the gateway's and random
#     ones cancel nothing: the sleep returns its row, no `canceling statement` text.
# Startup parameter injection on the wire (every non-allow-listed parameter dropped, `user` and
# `database` from the binding) is asserted by the Rust test `pg_relay_startup_parameter_injection_is_not_forwarded`
# in services/gateway (psql cannot send arbitrary startup parameters); the same file holds
# Rust twins of the other probes against a real postgres:18 (`cargo nextest run -p ls-gateway pg_relay`).
# Checks: the ledger holds `db.session.opened` and a matching `db.session.closed` for each psql
# session and no `db.session.denied`; the oracle scans every output, the gateway log and the
# ledger export for the canary. Skips when the stack, psql or openssl is missing.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
gw_init

command -v psql >/dev/null 2>&1 || { echo "skip: psql is not installed"; exit 77; }
command -v openssl >/dev/null 2>&1 || { echo "skip: openssl is not installed"; exit 77; }

PG_HOST=127.0.0.1
PG_STACK_PORT=5432
ROLE="g10_$$"
DB="g10db_$$"
BINDING="g10app"
OWNER_USER="$(gw_env POSTGRES_USER)"
OWNER_DB="$(gw_env POSTGRES_DB)"
OWNER_PW_FILE="$GW_WORK/owner.pgpass"
printf '%s:%s:*:%s:%s\n' "$PG_HOST" "$PG_STACK_PORT" "$OWNER_USER" "$(gw_env POSTGRES_PASSWORD)" >"$OWNER_PW_FILE"
chmod 600 "$OWNER_PW_FILE"

# owner_psql ARGS...: psql as the stack's owner role (dev-only credentials), for setup only.
owner_psql() {
  PGPASSFILE="$OWNER_PW_FILE" psql -X -q -h "$PG_HOST" -p "$PG_STACK_PORT" -U "$OWNER_USER" -d "$OWNER_DB" "$@"
}

# The role's password is the canary. The statement goes through a private 0600 file.
python3 -I -c '
import sys
role, db, canary_file, out = sys.argv[1:5]
pw = open(canary_file).read().strip().replace("\x27", "\x27\x27")
with open(out, "w") as fh:
    fh.write("CREATE ROLE %s LOGIN PASSWORD \x27%s\x27;\n" % (role, pw))
' "$ROLE" "$DB" "$CANARY_FILE" "$GW_WORK/role.sql"
gw_on_exit "owner_psql -c 'DROP DATABASE IF EXISTS $DB' -c 'DROP ROLE IF EXISTS $ROLE' >/dev/null 2>&1"
owner_psql -v ON_ERROR_STOP=1 -f "$GW_WORK/role.sql" >/dev/null 2>"$GW_WORK/role.err" || gw_fail "could not create the case role"
rm -f "$GW_WORK/role.sql"
owner_psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE $DB OWNER $ROLE" >/dev/null 2>&1 || gw_fail "could not create the case database"

# TLS material for the listener: a throwaway self-signed certificate.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=localhost \
  -keyout "$GW_WORK/pg.key" -out "$GW_WORK/pg.crt" 2>/dev/null || gw_fail "openssl could not make a certificate"
PG_PORT="$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
export LOCKSMITH_GATEWAY_PG_LISTEN="127.0.0.1:$PG_PORT"
export LOCKSMITH_GATEWAY_PG_TLS_CERT="$GW_WORK/pg.crt" LOCKSMITH_GATEWAY_PG_TLS_KEY="$GW_WORK/pg.key"

# The Postgres binding replaces the relay binding gw_setup writes (same file, same gateway).
gw_bind() {
  GW_BINDINGS="$GW_WORK/bindings.toml"
  python3 -I -c '
import json, sys
org, sid, name, role, db, port, out = sys.argv[1:8]
q = json.dumps  # a JSON string is a valid TOML basic string
with open(out, "w") as fh:
    fh.write("org_id = %s\n[[pg]]\nname = %s\nsecret_id = %s\nhost = \"127.0.0.1\"\nport = %s\nuser = %s\n"
             "database = %s\ntls = \"disable\"\nallow_private_hosts = true\n"
             % (q(org), q(name), q(sid), port, q(role), q(db)))
' "$GW_ORG" "$GW_SECRET_ID" "$BINDING" "$ROLE" "$DB" "$PG_STACK_PORT" "$GW_BINDINGS"
}
gw_setup "http://127.0.0.1:9"
for _ in $(seq 1 100); do
  (exec 3<>"/dev/tcp/127.0.0.1/$PG_PORT") 2>/dev/null && break
  sleep 0.1
done
(exec 3<>"/dev/tcp/127.0.0.1/$PG_PORT") 2>/dev/null || gw_fail "the pg listener did not come up (see gateway.log)"

# The agent's password file: the token never goes on a command line or into the environment.
python3 -I -c '
import json, sys
t = json.load(open(sys.argv[1]))["access_token"]
with open(sys.argv[2], "w") as fh:
    fh.write("127.0.0.1:%s:*:*:%s\n" % (sys.argv[3], t.replace("\\", "\\\\").replace(":", "\\:")))
' "$GW_AGENT_HOME/agent.json" "$GW_WORK/agent.pgpass" "$PG_PORT"
chmod 600 "$GW_WORK/agent.pgpass"
: >"$ARTIFACT_DIR/results.txt"

# agent_psql NAME [EXTRA CONNINFO] -- ARGS...: psql as the agent through the gateway, hostile
# startup user; output to ARTIFACT_DIR/psql-NAME.out/.err; returns psql's exit code.
agent_psql() {
  local name="$1" extra="$2"
  shift 3
  env -i PATH="$PATH" HOME="$GW_AGENT_HOME" PGPASSFILE="$GW_WORK/agent.pgpass" PGCONNECT_TIMEOUT=15 \
    psql -X -At "host=127.0.0.1 port=$PG_PORT dbname=$BINDING user=postgres sslmode=require $extra" "$@" \
    >"$ARTIFACT_DIR/psql-$name.out" 2>"$ARTIFACT_DIR/psql-$name.err"
}

# Baseline: the session works and runs as the bound role, not the startup `user`.
agent_psql baseline "" -- -c 'SELECT current_user' || gw_fail "baseline: psql through the gateway failed (see psql-baseline.err)"
[[ "$(<"$ARTIFACT_DIR/psql-baseline.out")" == "$ROLE" ]] || gw_fail "baseline: current_user is not the bound role"
echo "baseline ok" >>"$ARTIFACT_DIR/results.txt"

# 1. Error and notice echo.
python3 -I -c '
import sys
pw = open(sys.argv[1]).read().strip().replace("\x27", "\x27\x27")
with open(sys.argv[2], "w") as fh:
    fh.write("DO $do$ BEGIN\n"
             "RAISE NOTICE \x27notice %%\x27, \x27%(p)s\x27 USING DETAIL = \x27%(p)s\x27, HINT = \x27hint %(p)s\x27;\n"
             "RAISE EXCEPTION \x27error %%\x27, \x27%(p)s\x27 USING DETAIL = \x27%(p)s\x27, HINT = \x27hint %(p)s\x27;\n"
             "END $do$;\n" % {"p": pw})
' "$CANARY_FILE" "$GW_WORK/raise.sql"
set +e
agent_psql raise "" -- -v VERBOSITY=verbose -f "$GW_WORK/raise.sql"
set -e
rm -f "$GW_WORK/raise.sql"
grep -q 'notice' "$ARTIFACT_DIR/psql-raise.err" || gw_fail "raise: the notice did not arrive (is the case broken?)"
grep -q '\[REDACTED' "$ARTIFACT_DIR/psql-raise.err" || gw_fail "raise: no [REDACTED marker in the relayed error and notice (is redaction on?)"
echo "raise ok" >>"$ARTIFACT_DIR/results.txt"

# 2. options role switch and replication startup parameter.
agent_psql options "options='-c role=postgres -c session_authorization=postgres -c search_path=evil'" -- \
  -c "SELECT current_user || '|' || session_user || '|' || current_setting('role') || '|' || current_setting('search_path')" ||
  gw_fail "options: the session was refused (the options are to be ignored, not to fail the session)"
[[ "$(<"$ARTIFACT_DIR/psql-options.out")" == "$ROLE|$ROLE|none|\"\$user\", public" ]] ||
  gw_fail "options: the client's options changed the upstream session"
if agent_psql replication "replication=database" -- -c 'SELECT 1'; then
  [[ "$(<"$ARTIFACT_DIR/psql-replication.out")" == 1 ]] || gw_fail "replication: unexpected output"
else
  gw_fail "replication: a replication startup parameter failed the session instead of being ignored"
fi
echo "options ok" >>"$ARTIFACT_DIR/results.txt"

# 3. Cancel with a guessed key. A background psql runs a sleep and prints its upstream pid.
(
  agent_psql sleeper "" -- -c 'SELECT pg_backend_pid()' -c 'SELECT pg_sleep(6), 42' || true
) &
sleeper=$!
for _ in $(seq 1 50); do
  [[ -s "$ARTIFACT_DIR/psql-sleeper.out" ]] && break
  sleep 0.1
done
upstream_pid="$(head -n 1 "$ARTIFACT_DIR/psql-sleeper.out" 2>/dev/null || true)"
[[ "$upstream_pid" =~ ^[0-9]+$ ]] || gw_fail "cancel: the sleeper did not report its upstream pid"
python3 -I - "$PG_PORT" "$upstream_pid" >"$ARTIFACT_DIR/cancel-guesses.out" 2>"$ARTIFACT_DIR/cancel-guesses.err" <<'PY' || gw_fail "cancel: the guesser failed (see cancel-guesses.err)"
import random, socket, ssl, struct, sys

port, upstream_pid = int(sys.argv[1]), int(sys.argv[2])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["postgresql"])
rnd = random.Random(0xC10)
pairs = [(upstream_pid, 0), (upstream_pid, 1), (upstream_pid, 0x7FFFFFFF), (0, 0), (-1, -1)]
pairs += [(upstream_pid, rnd.randint(-(2**31), 2**31 - 1)) for _ in range(20)]
pairs += [(rnd.randint(1, 2**31 - 1), rnd.randint(-(2**31), 2**31 - 1)) for _ in range(20)]
sent = 0
for pid, key in pairs:
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    raw.sendall(struct.pack("!ii", 8, 80877103))  # SSLRequest
    if raw.recv(1) != b"S":
        sys.exit("no TLS on the listener")
    tls = ctx.wrap_socket(raw, server_hostname="localhost")
    tls.sendall(struct.pack("!iiii", 16, 80877102, pid, key))  # CancelRequest
    tls.settimeout(10)
    try:
        data = tls.recv(1)  # the gateway answers nothing and closes
    except (ssl.SSLError, OSError):
        data = b""
    if data:
        sys.exit("the gateway answered a CancelRequest")
    tls.close()
    sent += 1
print("sent %d cancel requests" % sent)
PY
wait "$sleeper" || true
grep -q '|42$' "$ARTIFACT_DIR/psql-sleeper.out" || gw_fail "cancel: the sleeper's row never arrived (cancelled by a guess?)"
if grep -qi 'cancel' "$ARTIFACT_DIR/psql-sleeper.err"; then
  gw_fail "cancel: the sleeping query was cancelled by a guessed key"
fi
echo "cancel ok" >>"$ARTIFACT_DIR/results.txt"

# Ledger: every psql session is opened and closed, none denied.
sleep 1
gw_ledger final
opened="$(gw_ledger_count "$GW_LEDGER" db.session.opened)"
closed="$(gw_ledger_count "$GW_LEDGER" db.session.closed)"
[[ "$opened" -ge 5 ]] || gw_fail "ledger: $opened db.session.opened events (expected at least 5)"
[[ "$closed" == "$opened" ]] || gw_fail "ledger: $opened opened but $closed closed"
[[ "$(gw_ledger_count "$GW_LEDGER" db.session.denied)" == 0 ]] || gw_fail "ledger: a db.session.denied event for an allowed session"
echo "G10 ok"
