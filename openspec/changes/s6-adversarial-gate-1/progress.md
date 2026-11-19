# Progress: s6-adversarial-gate-1

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-18 18:49 worker
- Task: none - planning
- Verified: `openspec validate s6-adversarial-gate-1 --strict`, `bash scripts/tree-check.sh`, `bash scripts/check-task-edits.sh`
- Notes for next session: depends on s5-audit-ledger (ledger events, audit API and export are G2/G5/G6 surfaces and evidence). Groups 1-6 are [opus]. Do group 1 (oracle) before group 4 (redactor) so the judge always sees more than the redactor. Gateway cases live in `tests/adversarial/gateway/` and run via `run.sh gateway`; `run.sh all` must stay unchanged because the weekly `adversarial.yml` runs it without a stack (agents cannot edit workflows). No new Actions job (AGENTS.md CI policy): "green in CI" = fast tier in `just ci` plus `just adversarial-gate` in Local verification. Re-check wiremock release date at apply. Owner open questions: create the nightly routine; ANTHROPIC_API_KEY in the VM for live mode.

## 2026-11-18 worker (josie)
- Task: 1.1 - failed (2 attempts, evaluator FAIL both; WIP, not ticked)
- Verified: `bash tests/adversarial/run.sh selftest` -> pass; `bash tests/kit/leak_scan_test.sh` -> pass
- Notes for next session: oracle.py has all new forms (commit 33bdad9, WIP follow-up has gzip fail-closed fix). Remaining evaluator blockers: (1) `tests/adversarial/run.sh` ~line 79 calls `oracle.py scan` via positional path (`scan_paths`, strict=False), so "gzip budget exhausted" is only a stderr notice and exits 0 -> repro: GZIP_MAGIC*4096 + gzip(canary) (~12KB) reports clean. Make `rep.incomplete` strict in scan_paths (also the >50MB skip) or use `--dir` in run.sh. (2) perf: GZIP_MAX_ATTEMPTS=4096 makes repeated-magic input ~14x slower (44s at 16MB); decompress only the first ~64KB per offset, or cap total gzip input bytes and mark incomplete. Then re-evaluate and tick 1.1/1.2.

## 2026-11-19 08:40 lead
- Task: 1.1, 1.2 - done (rescue #318)
- Cause: positional scans (run.sh) treated an incomplete gzip view as a notice (exit 0). A gzip-looking header with no NUL made zlib read to the end of the data on every attempt (39 s at 16 MB). Independent Opus review then found more fail-open gaps, each fixed and given a selftest:
  - damaged members (bad CRC, corrupt tail) were dropped;
  - zero-window back-references, which `gzip -dc` decodes, were missed;
  - a canary split across members was missed, back-to-back, across NUL padding and in a tie with a false member;
  - the run-join NUL check was quadratic.
- Fix: in `oracle.py`:
  - scans are strict everywhere;
  - zlib input is capped at 100 MB in 64 KB chunks;
  - the oracle parses the gzip header itself and inflates raw deflate with a 32 KB zero preset dictionary;
  - bisection `salvage()` keeps the output of a damaged member;
  - adjacent members, including across NUL padding and ties, are scanned joined, with the joined bytes capped;
  - the committed `__pycache__` is removed and ignored.
- Verified:
  - `python3 -I tests/kit/oracle.py selftest` -> passed (3.5 s);
  - `bash tests/adversarial/run.sh selftest` -> PASS;
  - `bash tests/kit/leak_scan_test.sh` (stack up) -> all PASS;
  - `bash tests/adversarial/run.sh all` -> 8 passed, 1 skipped;
  - Opus evaluator PASS: 0 of about 200 fuzzed damaged members that `gzip -dc` recovers were missed, and every perf probe on inputs up to 50 MB finished in 6 s or less;
  - `just ci` -> see the PR comment.
- Notes for next session: group 2 next. A minor item is out of scope: the quoted-printable view is linear but takes about 14 s on 50 MB of `=41`.

## 2026-11-19 worker (harriet)
- Task: 2.1, 2.2, 2.3 - done
- Verified: `bash tests/adversarial/run.sh selftest` -> PASS; `bash tests/adversarial/run_test.sh` -> 16/16; `ADVERSARIAL_REQUIRE_ALL=1 run.sh all` without stack -> identical to main (A2 fails only because aws CLI is missing in the VM); live stack setup/login/relay check; `just ci` -> exit 0 (678 passed); Opus evaluator PASS
- Notes for next session: group 3 next (G1-G6 cases using gateway/lib.sh). Evaluator minor items: (a) run.sh failure log tail masks only the plain canary and the case log is not oracle-scanned; (b) `gw_cp` writes the agent response with the enrollment secret to ARTIFACT_DIR/setup/NN-agent.json before masking: write to GW_WORK first; (c) a register entry excuses its (case, encoding) anywhere in the artifacts; (d) the oracle labels one plain canary twice (utf8+percent+json and b64url-offset0), so task 3.4 must list each label. lib.sh rebuilds binaries per case unless LOCKSMITH_*_BIN is set.

## 2026-11-19 worker (harriet)
- Task: 3.2, 3.3 - done; 3.1 - built, not ticked
- Verified: live `ADVERSARIAL_REQUIRE_ALL=1 run.sh gateway G1|G2|G3` -> PASS; `cargo nextest -p ls-gateway` 62/62; `just ci` -> exit 0 (680 passed); Opus evaluator PASS for 3.2, 3.3 and the gateway fix
- Notes for next session: G2 found a real leak (gateway ignored `Transfer-Encoding: gzip, chunked`); fixed in relay.rs (commit 2f92851) with tests. Evaluator FAILed 3.1 because dump_proc wrote the gateway and api process environ (real host tokens) to artifacts; fixed (private copy in GW_WORK, only names kept) and G1 re-passes live, but it needs a re-evaluation before ticking 3.1. Minor: G2 should assert `[REDACTED` on successful replies; add unit tests for `chunked;x=1`, identity, non-ASCII TE. Next: 3.4-3.7 (G4-G6), then group 4.
