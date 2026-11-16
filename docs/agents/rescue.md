# Rescue (Opus orchestrator, 2x daily)

The worker escalates a task to rescue after two failed attempts, even after an independent evaluator and a tier escalation.

1. **Fast exit.** Run `gh api 'repos/locksmith-hq/locksmith/issues?labels=needs-rescue&state=open'`. If the list is empty, reply `nothing to rescue` and stop. Skip run-meta and logging so an empty run stays cheap.
2. Run `bash scripts/run-meta.sh start rescue`. Rescue only the **oldest** issue, one per run.
3. **Read.** Read the issue and all its comments, then check out its branch. On that branch, read:
   - proposal.md, design.md, tasks.md, and the last 5 entries of progress.md
   - CLAUDE.md and `openspec/config.yaml`
   - `git log -10`
   - the failing CI logs
4. **Diagnose before fixing.**
   - Reproduce the failure: run `just ci`, the task's verification command, and `just up` if the stack is needed.
   - Form one root-cause hypothesis and confirm it with evidence.
   - Decide whether the cause is the code or the **task itself** (wrong, impossible, or under-specified).
5. **Fix.**
   - Fix code or environment causes at the root.
   - You may delegate mechanical parts to `sonnet` or `haiku`. Keep the diagnosis and anything security-relevant yourself.
6. **Verify.**
   - Run the verification command and `just ci` (rerun once if it fails once).
   - Then an independent `opus` evaluator subagent checks the diff against the task, spec and security rules. It answers PASS or FAIL.
7. **On PASS:**
   - Tick the task.
   - Append a `rescue` progress entry: root cause, fix, how it was verified, and the lesson for future workers.
   - Commit and push once.
   - Comment the root cause, fix and metadata on the issue, then close it.
8. **If the task itself is wrong:** don't rewrite the task text. Open a `needs-owner` issue that proposes corrected text with evidence, link it from the rescue issue, and send a push notification.
9. **On FAIL:**
   - Append a progress entry with what you learned.
   - Comment `rescue-attempt` with your findings and the metadata.
   - After 2 rescue attempts on the same issue, add the `needs-owner` label and send a push notification saying what you need from the human.
10. **Log.** Post an agent-log comment with the metadata.
