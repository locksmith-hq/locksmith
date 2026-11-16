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

## L2 · 2026-11-16 · setup
- Evidence: worker session 53918f37-3e8f-5abd-9cc2-22f6be3719ec (2026-11-16 19:33Z). ghcr.io returned 403 in the cloud sandbox; `service docker start` failed while `dockerd &` worked; `test-web` failed until `npm ci` had run.
- Lesson: pull images from Docker Hub (for example `openbao/openbao:2.7.2`, not `ghcr.io/...`). Let `agent-preflight.sh` start Docker. Run `npm ci` in the background before `just ci` when `node_modules` is missing.
- Change: preflight checks for registries and node_modules; `npm ci` in `cloud-setup.sh`; the F0 compose default image should move to Docker Hub (worker: do this on the F0 branch).
- Measure: `friction` entries mentioning docker, ghcr or npm should reach 0 per worker run (check on or after 2026-11-23).

## L3 · 2026-11-16 · setup
- Evidence: same session. The smith-cli test `same_user_cannot_read_daemon_memory` failed because the cloud VM runs as root (CAP_SYS_PTRACE bypasses non-dumpable).
- Lesson: in the cloud VM, treat root-only differences as environmental. The test now skips itself when running as root, and GitHub CI (non-root) still covers it.
- Change: crates/smith-cli/tests/session.rs skips the test when uid is 0.
- Measure: the baseline `just ci` in the VM passes with no environmental failures (check on the next worker run).
