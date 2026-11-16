# Rules for every scheduled agent

Each scheduled routine (worker, rescue, review, health, research, learning) reads this file and its own role file **from origin/main**. Changes to these files go through a PR the owner merges. Agents never edit them on their own branches.

## Environment
- You run in a fresh Claude cloud VM with the repo cloned. You start with no memory, and anything you don't push is lost.
- GitHub works through REST only: `gh api repos/locksmith-hq/locksmith/...`. `gh pr` and `gh issue` (GraphQL) are blocked.
- First command of every run: `bash scripts/run-meta.sh start <kind>`.
- Second: `bash scripts/agent-preflight.sh`. It checks and fixes the Docker daemon, `just`, the toolchain, disk, network and `gh`. Fix any FAIL line before doing real work, and record each FIXED, FAIL or WARN line in `friction`.
- Then read the last 15 entries of `docs/agents/lessons.md` from origin/main (`git show origin/main:docs/agents/lessons.md`). Follow them unless your role file says otherwise.

## Don't get stuck
- **Long commands.** Run anything expected to take more than about 2 minutes in the background with a hard timeout (cold `cargo build`/`test`, `just ci`, `docker compose pull`, `cargo install`): use the Bash tool's `run_in_background`, or `timeout 900 <cmd> > /tmp/<name>.log 2>&1 &`. Do other useful work, such as reading files or preparing the next step, and check the log with `tail` until the command finishes. Never sit idle waiting on a foreground command.
- **Wait for state, not time.** Poll the thing you need instead of sleeping a fixed time. For example: `until docker info >/dev/null 2>&1; do sleep 2; done` with a timeout, or loop on `curl -fs <healthcheck>`.
- **No interactive prompts.** Use `-y` and `--yes`, set `CI=1`, use `--no-pager` and `GIT_EDITOR=true`, and never open an editor.
- **When to stop.** If the same command fails twice with the same error, stop retrying it, write down the error, and move to the evaluate-then-escalate loop or to a rescue.
- **Record lost time.** Every time you lose more than about 2 minutes, add a `friction` entry, even if the run succeeds. Examples: a daemon was down, a tool was missing, an allowlist blocked a host, a build ran in the foreground, a test was flaky, instructions were unclear, a search came back empty.

## Actions budget
The repo is private on GitHub Free: $12/month of Actions, and macOS minutes cost about 10x Linux. Every push triggers CI. So:
- Push each branch at most once per run.
- Never re-run or dispatch workflows.
- Verify locally in the VM. Local compute is free.

## Model tiers (Agent tool `model`)
- `haiku`: the fast execution engineer. Clearly defined, isolated tasks, research and searches, running tests and verification, repetitive edits.
- `sonnet`: feature code outside secret paths, integration tests, refactors. Untagged tasks start here.
- `opus`: `[opus]` tasks, and anything touching secrets, crypto, auth, RLS, the gateway or adversarial gates. Also used for diagnosis and review.
- When unsure, go one tier up.

## Run metadata (on every agent-log comment and every issue you open)
End each comment or issue body with ONE ```yaml fenced block. Inside it, put the output of `bash scripts/run-meta.sh report` (plain YAML with no fences), then append the fields only you know:

```yaml
  orchestrator: <model you run on>
  outcome: done | failed | rescue | blocked | idle | ci-fix | healthy | nothing-to-rescue | learned | no-fix
  change: <id or none>
  task: <id or none>
  attempts: <n>
  evaluator: PASS | FAIL | n/a
  just_ci_s: <seconds of the last just ci, or n/a>
  tests: "<passed>/<total> or n/a"
  ci_run: <Actions run URL for your push, or none>
  subagents:
    - {role: implementer|evaluator|tester|research|diagnosis, tier: haiku|sonnet|opus, duration_ms: <n>, tokens: <n>, tool_uses: <n>, result: ok|fail}
  escalations: <e.g. "sonnet->opus", or none>
  friction:
    - {what: "<short description>", lost_s: <seconds, estimate allowed>, fix_idea: "<one line>"}
```

If you implemented a task yourself instead of delegating, list it as `{role: implementer, tier: <your model>, self: true}`. Take `duration_ms`, `tokens` and `tool_uses` from the usage each Agent result reports. Write `unknown` if it doesn't report them, and never estimate. Never put secrets in metadata.

## Logs
- `openspec/changes/<id>/progress.md` on the change branch is append-only, and `scripts/check-task-edits.sh` enforces this.
  - Read the last entries before working.
  - Append one entry before your final commit, even on failure. Notes for the next session matter most on failures.
  - If the file is missing, create it with the same header as the other changes' files.
- The open issue labelled `agent-log` gets one comment per run: a 1–3 line summary, links, and the metadata block. If the issue is missing, create it with the title "Agent run log".

## Owner decisions (human only)
Raise one only when a human must decide:
- an owner-gate task
- conflicting design options
- a merge is needed to unblock work
- a security problem
- an issue that Opus rescue failed twice

How to raise one:
1. Open an issue labelled `needs-owner` with the options and your recommendation, unless an open one has the same title. The `owner-alert` workflow then @mentions the owner, and GitHub emails them.
2. Load `PushNotification` via ToolSearch `select:PushNotification` and send one line under 200 characters that leads with the decision. If it's unavailable, write `push: unavailable` in the issue.
3. Never raise one for routine progress or failures you can retry.

## Task list rules
- In tasks.md, only flip `- [ ]` and `- [x]`. Never edit, add, remove or reorder task text.
- Tick a task only after its verification command and the independent evaluator both passed in this run.

## Hard rules
- Push only to `claude/*` branches. Never push to main, merge, force-push, or delete branches or tags.
- If a push is rejected as non-fast-forward, run `git pull --rebase` once, then `just task-guard`, then push again.
- Never mark a PR ready, and never approve one.
- Never write secret values anywhere.
- Never change repository, Actions or account settings.
- Never create, delete, enable, disable or reschedule any routine or scheduled task. Schedule changes need the owner's approval: propose them in a `needs-owner` issue.
- Commit messages end with `Co-Authored-By: Claude <noreply@anthropic.com>`. PR bodies end with `Generated with Claude Code`.
