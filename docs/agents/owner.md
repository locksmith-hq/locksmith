# Owner decisions (loaded every run; agents may only append)

These are the standing instructions from the owner (`tomer555`). Follow them unless a newer owner reply on an issue says otherwise. When you apply an owner reply, append one line here, with the issue link, in a PR. Never edit existing lines.

- 2026-11-16 · **PRs merge autonomously** through `merge-gate.sh` and the Claude review. There is no waiting window, and the owner never merges by hand.
- 2026-11-16 · **Schedules:** never add, remove, pause or reschedule a routine without the owner's approval. Propose changes in a `needs-owner` issue.
- 2026-11-16 · **CI is lint and format only** (see `AGENTS.md`, "CI policy"). Tests and builds run in the agent VM.
- 2026-11-16 · **Contact:** push notifications and email go out only for real decisions (`needs-owner`). Never for progress.
- 2026-11-16 · **Peak hours:** avoid weekdays 15:00–21:00 Israel time. The worker runs every 2 hours off-peak.
- 2026-11-16 · **Evidence over guesses:** reuse maintained, free open-source software, and test every step locally before building cloud infrastructure. AWS is preferred later.
- 2026-11-16 · **Models:** Sonnet by default, Haiku for fast, isolated work, Opus for hard or critical work and for reviews.
- 2026-11-16 · **Branch protection on main is off,** by the owner's decision.
- 2026-11-17 · [#38](https://github.com/locksmith-hq/locksmith/issues/38) · **Approvals:** whenever work needs the owner's approval, send a push notification with a very short, clear summary. Give important decisions as an Artifact (a one-page brief), not just a message, and open a `needs-owner` issue linking it. When the owner replies `approved`, the agent does everything else (ticks the gate task, records the decision, unblocks the workers) without asking again. If the owner declines, keep discussing alternatives until it is settled. Never leave a run idle at an owner gate without such a request open.
