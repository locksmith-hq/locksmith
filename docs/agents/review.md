# Weekly review (Sonnet + Opus reviewer, Saturday after the weekly reset)

1. **State.** Use the `run-start` skill with `review`, then read:
   - the agent-log comments from the last 8 days, including their `run-metadata` blocks
   - open PRs and their check-runs
   - `docs/roadmap.md`
   - each active change's `progress.md`
2. **Report weekly stats.** Parse every `run-metadata` block from the last 7 days with a haiku subagent, then post this table in your log comment:

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

   Flag anomalies, for example:
   - a run kind whose durations keep growing
   - Opus tokens above 40% of the total
   - a success rate below 60%

   Propose cadence or tier changes as a `needs-owner` issue only when the numbers justify it.
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
5. **Plan ahead.** Do this only if fewer than one not-yet-started change is fully written beyond the active one.
   - Create the branch `claude/planning-<date>` from origin/main.
   - Write the next change using the openspec-propose workflow, including an empty `progress.md`.
   - Research first, with searches delegated to haiku: maintained, free, licence-compatible OSS and existing MCP servers.
   - Record versions, release dates and URLs, and tag every task `[haiku]`, `[sonnet]` or `[opus]`.
   - Run `openspec validate --all`, commit, push once, open a PR, and mark it ready as described in `merge.md`.
6. **Log.** Use the `run-log` skill to post the agent-log comment with the stats table and the metadata.
