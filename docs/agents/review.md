# Weekly review (Sonnet + Opus reviewer, Saturday after the weekly reset)

1. **State.** Use the `run-start` skill with `review`, then read:
   - agent-log comments from the last 8 days
   - open PRs and their check-runs
   - `docs/roadmap.md`
   - each active change's `progress.md`
2. **Weekly stats.** With a haiku subagent, parse the last 7 days of `run-metadata` blocks into this table:

   | metric | value |
   |---|---|
   | runs by kind | |
   | outcome counts | |
   | success rate | |
   | median and p90 duration_s | |
   | tasks done | |
   | escalations and rescues | |
   | subagent tokens by tier (sum) | |
   | subagent count by role | |
   | friction: total lost_s, top 3 causes | |

   Flag anomalies:
   - a run kind whose durations keep growing
   - Opus tokens above 40% of the total
   - a success rate below 60%

   If the numbers justify it, propose cadence or tier changes in a `needs-owner` issue.
3. **Re-verify each open `claude/change-*` branch.**
   - With a haiku subagent, run the verification commands of the ticked tasks; the PR's CI checks cover `just ci`.
   - Untick anything that fails.
   - Append a `review` progress entry.
4. **Plan ahead.** Do this only if `bash scripts/change-status.sh --ready` lists fewer than three changes.
   - Lock one: `run-lock.sh claim review-<session> $(bash scripts/change-status.sh --plannable)` (release at end).
   - Branch `claude/planning-<id>` from origin/main; set `x-depends_on: [..]` in `.openspec.yaml`.
   - Write the next change using the openspec-propose workflow, including an empty `progress.md`.
   - Research first (haiku searches): maintained, free, licence-compatible OSS and MCP servers.
   - Record versions, release dates and URLs; tag every task with its tier.
   - Run `openspec validate --all`, commit, push once, open a PR, finish it (`finish-pr` skill).
5. **Log.** Use the `run-log` skill to post the agent-log comment with the stats table and the metadata.
