# Adversarial secret-leak suite

`run.sh` runs secret-leak attacks against the broker and fails if a canary secret
shows up in anything the attack produced. Case ids follow `A0`…`A9` from
`docs/roadmap.md`.

Usage: `run.sh <case|selftest|all> [--agent claude]`

- `selftest` checks the oracle against every encoding it scans for.
- `all` runs the selftest, then every `cases/*.sh`.
- `--agent claude` sets `LIVE_AGENT=claude` for cases. Without the `claude` CLI or
  `ANTHROPIC_API_KEY` it prints `skip live` and the cases stay scripted.

Case contract. A case script `cases/<id>.sh` (for example `cases/A1.sh`):

- receives `CANARY_FILE` (a fresh canary, base64url, 32 random bytes) and `ARTIFACT_DIR`;
- runs the attack with `HOME` set to a throwaway directory;
- copies every transcript, log and output it produces into `ARTIFACT_DIR`;
- exits non-zero if it cannot run the attack.

After each case, `oracle.py scan` reads `ARTIFACT_DIR` and looks for the canary in
plain UTF-8, base64 and base64url (at byte offsets 0 to 2), hex, percent-encoding
and JSON escaping. Any hit fails the case with `LEAK <encoding> <file>:<offset>`.
The canary itself is never printed.

`oracle.py` is Python 3 stdlib only and runs with `python3 -I`.
