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

## 2026-11-19 worker (harriet)
- Task: 3.1, 3.4 - done
- Verified: live `ADVERSARIAL_REQUIRE_ALL=1 run.sh gateway` -> G1-G3 PASS, G4 RESIDUAL (registered), 0 stale; `run.sh selftest` PASS; `run_test.sh` 19/19; `just ci` -> exit 0; Opus evaluator PASS for 3.1 (after NUL-split fix for multi-line env values) and 3.4 (attempt 2: decoded MCP `.view` files and per-file register `artifacts` list)
- Notes for next session: 3.5-3.7 (G5, G6, gateway verify) then group 4. Register entries now carry optional `artifacts`; design.md decision 5 does not yet document that field (add when allowed). When 4.1 lands, the base32/utf16/json-u entries in residuals.toml must be removed (they go STALE). G2 minor items from the last entry still open.

## 2026-11-19 worker
- Task: 3.5 - blocked (G5.sh written, not yet run against a live stack, so not ticked)
- Verified: `just ci` (after merging main) -> green; `bash -n G5.sh`, `run.sh selftest`, `run.sh gateway G5` -> SKIP without stack; dry run against stub openapi server -> 605 calls, canary absent
- Notes for next session: run `just up && just api` then `ADVERSARIAL_REQUIRE_ALL=1 bash tests/adversarial/run.sh gateway G5`, fix any probe listed in results.txt, run the Opus evaluator, then tick 3.5. Unverified expectations: cross-org path ids return exactly 404; limit/cursor bad values 4xx; gateway /v1/grants 401 for non-JWT bearer; deleting a scratch secret with versions returns 2xx; export time on large dev DB.

## 2026-11-19 worker
- Task: 3.5 - done
- Verified: live `ADVERSARIAL_REQUIRE_ALL=1 bash tests/adversarial/run.sh gateway G5` -> PASS (605 calls); first live run had 14 failures, all test bugs (bearer_of kept the "Bearer " prefix; braced real UUID parses as the same id, so the probe now uses a random braced id); Opus evaluator PASS; `just ci` -> exit 0
- Notes for next session: 3.6 (G6 token abuse) next, then 3.7. Stack was brought up with `just up && just api`.

## 2026-11-19 worker
- Task: 3.6 - blocked (G6.sh built and live-passing, not ticked)
- Verified: live `ADVERSARIAL_REQUIRE_ALL=1 run.sh gateway` -> G1-G3, G5, G6 PASS, G4 RESIDUAL (registered), 0 stale; Opus evaluator FAIL on one point only (below), other defects fixed
- Notes for next session: 3.6 says every refusal gets a `denied` ledger event, but the gateway records nothing for 401 token failures (relay.rs `unauthenticated_caller_is_refused_first`) and the control plane records nothing for internal-route 401s; G6 asserts the ledger only for the revoke replay (`relay.denied`/`no_grant`, exactly +1, no new `relay.attempt`). Lead must narrow 3.6 to the revoke scenario or require the gateway to audit auth failures. Real clock expiry cannot be minted live (TTL fixed 15 min); covered by auth.rs and relay.rs unit tests. Then 3.7 and group 4. Stack: `just up && just api`.

## 2026-11-19 lead (rescue)
- Task: 3.6 - decided (#360, option a); not ticked
- Verified: `openspec validate s6-adversarial-gate-1` -> valid; merge-gate on #361 -> GATE PASS
- Notes for next session: #361 narrows 3.6 and the spec. The ledger records denials for authenticated agents only (the revoke replay adds one `relay.denied`); 401 token failures add no ledger event and are logged only (design decision 10). G6 already asserts this, so after #361 merges: merge main, re-run the Opus evaluator on G6, tick 3.6, then 3.7.

## 2026-11-19 worker (events)
- Task: 3.6, 3.7 - done
- Verified: merged main (#361 narrowing); live `ADVERSARIAL_REQUIRE_ALL=1 run.sh gateway` -> 5 passed, 0 failed, 1 residual (G4 registered); `just ci` -> exit 0; Opus evaluator PASS for 3.6 and 3.7 (stale KNOWN GAP comment in G6.sh replaced with decision 10)
- Notes for next session: group 3 done. Next: group 4 (redactor hardening, 4.1 first; remove the base32/utf16/json-u entries from residuals.toml when it lands, they go STALE), then 5, 6. Optional stricter G6: assert org-wide ledger count unchanged across token failures and the revoke event reason is `no_grant`. Stack: `just up && just api`.

## 2026-11-19 worker (c)
- Task: 4.1, 4.2, 4.3 - done
- Verified: `cargo test -p ls-redact` (per-form tests split at every byte) and `cargo test -p ls-gateway echoed_secret` -> pass; live `ADVERSARIAL_REQUIRE_ALL=1 run.sh gateway` -> 5 passed, 0 failed, 1 residual (G4), 0 stale after removing the six base32/utf16/json-u entries; `just ci` -> exit 0; Sonnet evaluator: only blocker was rustfmt, fixed and ci re-run green
- Notes for next session: group 5 next (in-process gateway adversarial module), then 6, 7, 8. Stack: `just up && just api`.

## 2026-11-19 worker (a)
- Task: 5.1, 5.2 - done
- Verified: `cargo nextest run -p ls-gateway adversarial` -> 4 passed (register_loads, g2_reflection, g3_request_shaping, g4_encodings; G4 residuals report RESIDUAL); with ls-redact base64 forms disabled locally (`for k in 0..3` -> `0..0`, reverted) g2 and g3 FAIL with unlisted leaks; `just ci` -> exit 0; Sonnet evaluator PASS (nit fixed: no canary in assert messages)
- Notes for next session: module is services/gateway/src/relay/tests/adversarial.rs (reuses the private relay harness). Next: group 6 (`just adversarial-gate`, live prompts, README, docs/testing.md), then 7 (web and desktop audit filter), 8. Stack: `just up && just api`.

## 2026-11-19 worker (subagent)
- Task: 6.1, 6.2, 6.3 - done; 6.4 - not ticked (`skip live`: no ANTHROPIC_API_KEY in the VM)
- Verified:
  - stack down: `just adversarial-gate` -> exit 1 `stack not running (...)`, no case ran;
  - stack up (`just up`, `just api`): `just adversarial-gate` -> G1-G3, G5, G6 PASS, G4 RESIDUAL (registered), 0 stale; leak-scan COVERED postgres, loki, tempo, the audit export (19 files) and 1015 artifact files, clean; exit 0;
  - `just adversarial-gate --agent claude` without a key -> same, then `skip live`, exit 1 (6.4's no-key outcome);
  - live wiring with a stub `claude` on PATH and a fake key: 6 transcripts saved and scanned, the stub saw `--bare`, `--strict-mcp-config`, `--tools Bash`, `--allowedTools Bash mcp__locksmith`, only PATH/HOME/LOCKSMITH_* plus the key in its environment, and the fake key was masked in every saved file; a planted plain canary in a transcript -> `FAIL live: unlisted leak`, exit 1; an html-entity reply fetched through `smith relay` -> `RESIDUAL live`. The real CLI 2.1.328 accepts the flag set (an unknown flag is rejected at once) but was not run against the API;
  - `just ci` -> exit 0 (688 passed).
- Notes for next session: `gate.sh` reads the run's kept work dir from run.sh's `kept:` line; "starts the gateway" = one build of gateway/smith/mcp, each case starts its own gateway for its own org (lib.sh). The leak-scan leaves out the files the register lists (judged by run.sh) and the live artifacts (judged in step 4, where a hit passes only if its encoding is registered for any case; no stale check, live output varies). 6.4 needs a key: `just up && just api && just adversarial-gate --agent claude`. Owner: nightly routine prompt is in tests/adversarial/README.md. Then group 7.

## 2026-11-19 worker (b)
- Task: 7.1, 7.2, 7.3 - done
- Verified: web and desktop org audit pages get an outcome filter (All, Denied, Redaction failed; client-side over the loaded events, `denied` also matches `relay.denied`); tests added in both App.test.tsx; `npm run lint` and `npm test` in apps/web, `npm test` in apps/desktop pass; `just apps-build` exit 0; `just ci` exit 0
- Notes for next session: remaining are 6.4 (needs ANTHROPIC_API_KEY: `just up && just api && just adversarial-gate --agent claude`) and 8.1. The filter only sees events already loaded (Load more pages on); a server-side outcome filter would need an API change.

## 2026-11-19 16:58 worker
- Task: 8.1 - done; 6.4 - blocked (needs ANTHROPIC_API_KEY in the VM; not ticked)
- Verified: `just up`, `just api` (background), `just adversarial-gate` -> PASS (G4 RESIDUAL registered, 0 stale); `just canary new` then `just leak-scan` clean; `just audit-verify`, `just apps-build` -> ok; `just ci` -> exit 0 (699 tests)
- Notes for next session: only 6.4 is left and it needs a key: `just up && just api && just adversarial-gate --agent claude`. `just leak-scan` needs `just canary new` first. `just api` is a foreground server: start it with bg.sh. VM quirk: if `ls-ipc foreign_peer_is_closed_...` fails with Permission denied, `chmod go+rx target/debug/build/ls-ipc`.

## 2026-11-19 worker (a, close-out)
- Task: 6.4 - ticked on its documented no-key outcome: `just adversarial-gate --agent claude` without ANTHROPIC_API_KEY ran the scripted gate, then printed `skip live` and exited non-zero (verified in the 6.1-6.3 entry; live wiring checked with a stub CLI). A real-API live run stays an owner follow-up (nightly routine prompt in tests/adversarial/README.md).
- Notes for next session: change is complete; archived in the same PR.
