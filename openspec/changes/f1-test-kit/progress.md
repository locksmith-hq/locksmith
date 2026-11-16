# Progress: f1-test-kit

Append-only session log for this change. Each scheduled or human session adds one entry at the end
before its final commit, and every session reads the last entries plus `git log` before starting.
Format:

## <UTC date time> <worker|review|human>
- Task: <id> - <done|failed|blocked|ci-fix>
- Verified: <command> -> <result>
- Notes for next session: <what to know, what to try next, traps found>


## 2026-11-16 worker
- Task: 1.1-1.4 - done
- Verified: oracle.py selftest, tests/adversarial/run.sh all (8 pass, 1 skip A2), tests/kit/leak_scan_test.sh (all pass vs live stack), just ci -> green; Opus evaluator PASS
- Notes for next session: Next is section 2 (nextest, dev-deps, tests/e2e). Docker Hub gave 429; pulled postgres:18 and wiremock from mirror.gcr.io, retagged, ran compose with --pull never. LEAK lines use oracle labels (b64-offset0), not "base64" as spec example. Evaluator minors: leak-scan recipe overrides user PG* vars; Loki/Tempo window 24h not shown in --explain; unreadable dirs under --dir skipped silently.
