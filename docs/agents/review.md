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
   | Actions minutes this month (billing API, else "unavailable") | |

   Flag anomalies:
   - a run kind whose durations keep growing
   - Opus tokens above 40% of the total
   - a success rate below 60%

   If the numbers justify it, propose cadence or tier changes in a `needs-owner` issue.
3. **Re-verify each open `claude/change-*` branch.**
   - With a haiku subagent, run `just ci` and the verification commands of the ticked tasks.
   - Untick anything that fails.
   - Append a `review` progress entry.
4. **Quality review.** An opus subagent reviews each PR diff against its base. It checks:
   - the CLAUDE.md security rules
   - the `openspec/config.yaml` rules (evidence table, OSS-used table, local verification)
   - reinvented wheels
   - edited task text

   Push small safe fixes together with the progress entry in one push. Post the remaining findings as a PR comment. Raise anything critical as an owner decision.
5. **Plan ahead.** Do this only if `bash scripts/change-status.sh --ready` lists fewer than two changes.
   - Take the next roadmap change whose prerequisites are archived or in review, and lock its id (`run-lock.sh acquire review-<session> <id>`; if busy, take the next; release at end).
   - Branch `claude/planning-<id>` from origin/main; set `x-depends_on: [..]` in `.openspec.yaml`.
   - Write the next change using the openspec-propose workflow, including an empty `progress.md`.
   - Research first (haiku searches): maintained, free, licence-compatible OSS and MCP servers.
   - Record versions, release dates and URLs; tag every task with its tier.
   - Run `openspec validate --all`, commit, push once, open a PR, mark it ready as described in `merge.md`.
6. **Log.** Use the `run-log` skill to post the agent-log comment with the stats table and the metadata.
