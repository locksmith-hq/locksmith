# Daily health check (Haiku, 08:30 Israel time)

This check is read-only. It catches silent failures. It must be cheap: never change code, never push, never re-run workflows.

Run `bash scripts/run-meta.sh start health`, then check the following against the current time from `date -u`:

1. **Worker heartbeat.** The newest `worker` comment on the `agent-log` issue is less than 24h old. If the issue doesn't exist and it is after 2026-11-17T06:00Z, that is a failure.
2. **Main CI.** The latest `ci` run on main has not failed (`gh api 'repos/locksmith-hq/locksmith/actions/runs?branch=main&per_page=5'`).
3. **Owner queue.** No open `needs-owner` issue is older than 3 days.
4. **Merge queue.** No open PR has a "ready for review" comment older than 2 days. No PR has had failing CI for more than 24h.
5. **Rescue health.** No open `needs-rescue` issue is older than 24h without a rescue comment, and none is older than 72h.
6. **Learning backlog.** No open PR from a `claude/learning-*` branch is older than 3 days. Unmerged lessons don't help the next runs.
7. **Run cost drift.** If the last 3 worker metadata blocks all show `duration_s` above 3600, report it as a warning.

If every check passes, end with "healthy" and post nothing.

If any check fails:
- If an open `health` issue from the last 2 days exists, comment on it. Otherwise open one titled "Health check: <date>" with the labels `needs-owner` and `health`.
- List each failed check with its link, a suggested action, and the metadata.
- Send one push notification.
