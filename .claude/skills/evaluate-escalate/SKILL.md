---
name: evaluate-escalate
description: The implement → independent evaluate → escalate-one-tier loop for doing one OpenSpec task (or fixing CI / main). Use for every task a worker or lead rescue does; includes how to open a needs-rescue issue when both attempts fail.
---

# Evaluate, then escalate

## Tiers (Agent tool `model`)
- `haiku`: isolated, well-defined work and repetitive edits.
- `sonnet`: default for untagged tasks.
- `opus`: tasks tagged `[opus]`, and anything touching secrets, crypto, auth, RLS, the gateway or adversarial gates.

You may implement small tasks yourself (`self: true` in run-log); step 3 still applies.

Run every implementer and evaluator subagent in the foreground: never `run_in_background`, and never end your turn while a subagent runs. A cloud run stops when your turn ends, so unpushed work is lost (worker A, 2026-11-18 12:06).

## Loop
1. **Implement.** Give the implementer:
   - the exact task text, the design excerpt, the files and the verification command;
   - the rules: reuse OSS from `docs/research/oss-building-blocks.md`, use real versions from crates.io or GitHub, and never print secrets.
2. **Verify it yourself.** Run the task's verification command and `just ci`. Use the `long-commands` skill if either is slow.
3. **Evaluate.** A separate subagent, never the implementer, runs on `sonnet`, or on `opus` for `[opus]` tasks. Give it the task, the spec excerpt, `git diff`, the verification output and the AGENTS.md security rules. It answers PASS or FAIL with reasons, checking:
   - the task is really done, not stubbed;
   - the tests exercise real behaviour;
   - no secret can leak;
   - no reinvented OSS;
   - the package versions are real.
4. Tick only the checkbox, after verification and the evaluator pass. Never tick or mark ready with `evaluator: n/a`.
5. Otherwise, make attempt 2 one tier up (haiku → sonnet → opus). Give the new implementer the evaluator's reasons, failing output and attempt-1 diff; repeat steps 2–4.
6. If attempt 2 also fails:
   - commit with a `WIP:` message if the code builds, otherwise `git stash`;
   - write a progress entry;
   - open a `needs-rescue` issue titled `Rescue: <change> <task>`, or comment on an existing one. Its first line is one plain sentence: what is stuck and why (the board shows it). Then include the branch, the tiers tried, the evaluator's reasons, up to 60 lines of failing output, and your diagnosis.

   Don't notify the owner; the lead routine rescues it. Move on to an independent task, or stop.
