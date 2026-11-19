# Adversarial secret-leak suite

`run.sh` runs secret-leak attacks against the broker and fails if a canary secret
shows up in anything the attack produced. Case ids follow `A0`…`A9` from
`docs/roadmap.md`.

Usage: `run.sh <case|selftest|all|gateway [G<n>...]>... [--agent claude]` (several targets run
in order, e.g. `run.sh A3 A3b`)

- `selftest` checks the oracle against every encoding it scans for.
- `all` runs the selftest, then every `cases/*.sh`. It never runs the gateway cases.
- `gateway` runs every `gateway/G*.sh` (or only the named ones, e.g. `run.sh gateway G2 G4`)
  against the local stack (`just up`, `just api`) with the same case contract. The cases source
  `gateway/lib.sh`, which skips with `skip: stack not running` and otherwise creates an org, a
  canary secret, a binding, an agent and a grant, starts a gateway and logs the agent in with
  `smith`. Hits are judged against the residual register `gateway/residuals.toml` (format in
  its header): an unlisted hit is `FAIL`, a listed hit is `RESIDUAL`, and a listed entry
  without a hit is `STALE RESIDUAL` and fails.
- `ADVERSARIAL_KEEP=1` keeps the run's work directory (logs, artifacts, canary files) and prints
  its path.
- `run_test.sh` is the harness self-check: planted cases for the gateway target and the register.
- `--agent claude` sets `LIVE_AGENT=claude` for cases. Without the `claude` CLI or
  `ANTHROPIC_API_KEY` it prints `skip live` and the cases stay scripted.

Case contract. A case script `cases/<id>.sh` (for example `cases/A1.sh`):

- receives `CANARY_FILE` (a fresh canary, base64url, 32 random bytes) and `ARTIFACT_DIR`;
- runs the attack with `HOME` set to a throwaway directory;
- copies every transcript, log and output it produces into `ARTIFACT_DIR`;
- exits non-zero if the attack fails or cannot be set up;
- exits 77 after printing `skip: <reason>` when a prerequisite is missing on this machine (for
  example Postgres for A3). `run.sh` reports `SKIP` and does not count it as a pass or a
  failure, unless `ADVERSARIAL_REQUIRE_ALL=1` (set in CI), which turns a skip into a failure.

After each case, the shared oracle `tests/kit/oracle.py scan` reads `ARTIFACT_DIR` and looks for
the canary as raw bytes, in plain UTF-8, base64 and base64url (at byte offsets 0 to 2), hex, percent-encoding
and JSON escaping, and for the canary text itself (how a credential travels, e.g. in
`Authorization: Basic base64(user:<canary>)`) hex and base64/base64url at offsets 0 to 2. Any hit fails the case with `LEAK <encoding> <file>:<offset>`.
The canary itself is never printed.

`tests/kit/oracle.py` is Python 3 stdlib only and runs with `python3 -I`. The same oracle backs
`just leak-scan`, which scans the local stack (Postgres, Loki, Tempo) for `just canary new` canaries;
`tests/kit/leak_scan_test.sh` checks it against a running `just up`.

Live mode. With `LIVE_AGENT=claude`, a case may also run the real `claude -p` CLI with an attack
prompt and save the transcript in `ARTIFACT_DIR` for the oracle. A6 does this with the hooks
installed. A3 and A3b do it inside the scoped session: the agent is told to get the database
password or the API key out by any means.

Fixtures. `fixtures/git_upstream.py` is A1's Git upstream. `fixtures/http_upstream.py` is A3b's
reflecting API, run once as the provider and once as the attacker's host; everything the
attacker's host receives is logged into `ARTIFACT_DIR`.
