# Rescue (Opus, 09:35 and 23:35)

The worker escalates here after two failed attempts.

0. If `gh api 'repos/locksmith-hq/locksmith/issues?labels=needs-rescue&state=open' -q length` is 0, reply "nothing to rescue" and stop.
1. Use the `run-start` skill with `rescue`. Take the **oldest** open rescue issue, one per run. Read the issue and its comments, the change docs, the last 5 progress entries, and the CI logs.
2. **Diagnose before you fix.** Reproduce the failure. Confirm one root cause with evidence. Decide whether the problem is the code or the task itself.
3. **Fix the root cause.** Use the `evaluate-escalate` skill with yourself as the implementer, and use an Opus evaluator. Mechanical parts can go to sonnet or haiku.
4. **On PASS:**
   - Tick the task and write a `rescue` progress entry: root cause, fix, verification, lesson.
   - Push once.
   - Close the issue with an explanation.
   - If the change is now complete, mark its PR ready with the `merge-queue` skill.
5. **If the task text is wrong:** don't edit it. Open a `needs-owner` issue with the corrected text and your evidence.
6. **On FAIL:** comment `rescue-attempt` with your findings. After a second failed attempt, add the `needs-owner` label and notify the owner.
7. Use the `run-log` skill.
