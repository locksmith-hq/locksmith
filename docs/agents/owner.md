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
- 2026-11-17 · [#38](https://github.com/locksmith-hq/locksmith/issues/38) · **Approvals:** for anything needing owner approval, send a push notification with a short, clear summary; for important decisions also an Artifact brief and a `needs-owner` issue linking it. When the owner replies `approved`, do the rest (tick the gate, record it, unblock workers). If declined, discuss alternatives until settled. Never idle at an owner gate without such a request open.
- 2026-11-17 · **Workers hourly, 24/7:** A at :05, B at :35; replaces the peak-hours line.
- 2026-11-17 · **Event-driven worker:** the `Worker (events)` routine runs on PR `ready-to-merge` labels and merges (author `tomer555`, base `main`); the hourly workers stay as the safety net.
- 2026-11-17 · **Event wake-ups:** review verdicts, merges, owner replies, red main CI and new rescue issues wake the event routines within minutes; hourly workers A and B stay as the safety net until the event path is proven.
- 2026-11-17 · [#112](https://github.com/locksmith-hq/locksmith/issues/112) · **Planning PRs:** approved: `claude/planning-*` PRs are exempt from merge-gate gate 1 (they add a change, not complete it). The gate script is owner-only, so the owner session must make that edit; until then planning PRs wait.
- 2026-11-17 · [#147](https://github.com/locksmith-hq/locksmith/issues/147) · **Go public:** the owner wants the repo prepared for publicity (a public repo removes the Actions-minutes limit). Agents prepare it (secret and history scan, licence, README, docs); only the owner flips visibility. Planning change to follow.
- 2026-11-17 · **Fewer workers:** events drive the work; Worker A runs every 4 hours as the safety net and Worker B is disabled until more than two changes are ready at once.
- 2026-11-18 · [#216](https://github.com/locksmith-hq/locksmith/issues/216) · **Actions minutes:** owner approved the minutes-saving fix (#146 is closed; change-sync on main now runs daily); keep CI to lint/hygiene and watch `scripts/actions-usage.py`.
- 2026-11-18 · **Owner replies:** every owner reply on a `needs-owner` issue wakes the lead. Until the owner approves, the lead keeps discussing on the issue; on approval it updates the OpenSpec plan, priorities and related issues, then closes the issue, which wakes workers (`lead.md` step 0).
