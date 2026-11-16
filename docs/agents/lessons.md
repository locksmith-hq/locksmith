# Lessons for scheduled agents

This file is append-only. Every scheduled agent reads the **last 15 entries** from origin/main before working, and follows them unless its role file says otherwise. The learning routine adds entries, and each one carries a measurable target. The owner merges every change.

Each entry has this format:

## L<n> · <YYYY-MM-DD> · <category>
- Evidence: <session id / run time / ≤5 log lines, no secrets>
- Lesson: <one imperative sentence>
- Change: <files changed, PR link>
- Measure: <metadata field> should become <target> (check on or after <date+7>)

## L0 · 2026-11-16 · flaky
- Evidence: locally, `just ci` failed on the first run after a commit, 4 times in one session. Reruns passed, and the failure could not be reproduced with output captured.
- Lesson: if `just ci` fails once, rerun it once before treating the failure as real, and record both results in the metadata.
- Change: a rerun-once rule in common.md and worker.md.
- Measure: weekly `flaky` count from rerun-once events should reach 0 after the flaky test is found and fixed. A learning run should identify the test from CI logs.

## L1 · 2026-11-16 · stuck-time
- Evidence: owner report. Agents lose time when they don't notice the Docker daemon is down, run long commands in the foreground, or wait without polling.
- Lesson: run `scripts/agent-preflight.sh` first, run commands over about 2 minutes in the background with a timeout and poll their log, and record every loss over about 2 minutes as `friction`.
- Change: `scripts/agent-preflight.sh`; a "Don't get stuck" section in common.md; the `friction` metadata field; the `stuck-time` category in learning.md.
- Measure: weekly summed `friction.lost_s` per worker run should stay below 300 (check on or after 2026-11-23).
