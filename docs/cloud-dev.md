# Running Locksmith work in Claude cloud sessions

Agent work runs in Claude Code cloud sessions and cloud scheduled tasks, not on a laptop.
Every fact below comes from the Claude Code docs (fetched 2026-11-16):
- https://code.claude.com/docs/en/claude-code-on-the-web.md
- https://code.claude.com/docs/en/cloud-environments.md
- https://code.claude.com/docs/en/routines.md

Items marked **[test]** are not documented and are checked on the first run.

## What a cloud session gives us
- **Machine:** Ubuntu 24.04 VM, about 4 vCPU, 16 GB RAM and 30 GB disk. It pauses when idle and is thrown away later. **Anything not pushed is lost.**
- **Preinstalled:** docker, dockerd and docker compose, Rust, Node 20 to 22, Python, and gcc/clang. Postgres 16 is installed but not used: we run Postgres 18 in compose, per A0.
- **Repo config that is honoured:**
  - `CLAUDE.md`, `.claude/settings.json` (hooks, permissions), `.mcp.json`, skills and agents.
  - A SessionStart hook runs when `CLAUDE_CODE_REMOTE=true`.
- **Ignored in the cloud:** `~/.claude`, local plugins, user-scope MCP servers.
- **Command time limits:** 2 min by default, up to 10 min on request, then backgrounded for up to 30 min. Raise them with `BASH_DEFAULT_TIMEOUT_MS` and `BASH_MAX_TIMEOUT_MS`.

## Environments

Create these at claude.ai/code → environment selector → New environment.

### 1. `locksmith-dev`: used by every worker run and interactive session
- **Network:** **Limited** with **Allow package managers** on. That allowlist already covers everything phase 0 to 3 needs:
  - crates.io, static.rust-lang.org and rustup.rs
  - registry.npmjs.org
  - pypi.org, for `uvx postgres-mcp`
  - Docker Hub, which hosts postgres, grafana/otel-lgtm, wiremock and mcp-grafana
  - ghcr.io, which hosts openbao (use `ghcr.io/openbao/openbao`, not quay.io, which is **not** on the list)
  - github.com, including release assets, and Ubuntu apt
- **Extra allowed domains:** none for now.
- **Environment variables:** `BASH_MAX_TIMEOUT_MS=600000`, `CARGO_TERM_COLOR=never`. **No secrets here.** Environment variables are readable by the model and by any command it runs.
- **Setup script:** contents of [`scripts/cloud-setup.sh`](../scripts/cloud-setup.sh). It installs build dependencies, `just`, the pinned toolchain, `cargo-nextest` and `openspec`, and pre-pulls the compose images. The images are cached between sessions; containers are not.
- **Starting the stack:** each session starts it with `just up`, which the F0 docs tell the agent to run. A SessionStart hook can automate this once F0 lands. **[test]** Whether Docker in the VM runs the full stack (lgtm needs about 1 to 2 GB RAM).

### 2. `locksmith-research`: used by the weekly review and planning runs
- **Network:** Limited, with package managers, plus these documentation hosts:
  - `docs.aws.amazon.com`, `aws.amazon.com`
  - `www.postgresql.org`
  - `docs.rs`
  - `*.github.io`
  - `code.claude.com`, `docs.claude.com`
  - `nexte.st`, `insta.rs`, `www.cedarpolicy.com`, `openbao.org`, `grafana.com`
- **Why separate:** the worker never needs open web access, so a prompt-injected web page can't reach a session that runs code with a wider network. **[test]** Whether WebSearch and WebFetch obey the environment allowlist. If they do, add domains here as research needs them; never switch to Full.

### 3. Later: `locksmith-aws-dev`, from phase 4 (P1)
- Deploys to AWS run from **GitHub Actions using OIDC**, not from Claude sessions.
- The reason: AWS requests are signed with SigV4, so they can't use the cloud "network secrets" proxy, and putting AWS keys in environment variables would expose them to the model. That breaks the very rule this product exists to enforce.
- Claude sessions get read-only AWS access only, through Locksmith itself once D2 (AWS STS) lands. This is dogfooding.

## Secrets
- **None are needed through phase S3.** All local stack credentials are dummy values in `infra/compose/.env.example`.
- **S4's first real API demo (Langfuse):** store the key as a **network secret** on `locksmith-dev`, bound to the Langfuse host as a custom `Authorization` header. The proxy attaches it after the request leaves the VM, so the key never enters the VM. Later, Locksmith's own gateway replaces this.
- **GitHub:** cloud sessions use the GitHub proxy with your connected identity. `GITHUB_TOKEN` is a placeholder. `gh api` (REST) works, but `gh pr` and `gh issue`, which use GraphQL, are rejected. So PRs are opened with `gh api repos/locksmith-hq/locksmith/pulls`.

## Scheduled tasks in the cloud
These replace the desktop scheduled tasks once the first run is verified.

### What each run may do
- Push only to `claude/change-<id>` (and `claude/planning-<date>`), then open a **draft** PR. Never push to `main`, merge or force-push.
- **Risk to accept or fix:** branch protection on a private repo needs GitHub Pro or Team. The org is on the free plan, so the API returns 403. Until it is upgraded, or the repo goes public (it is meant to be open source), only the prompt keeps runs off `main`.

### Budget
- `get_usage` exists only in the desktop app, so cloud runs **cannot check usage**. The budget is set by cadence instead:
  - worker: 3 runs a day
  - weekly review: 1 run a week
- Every run counts against the plan limits. Adjust the cadence after a week of real numbers.

### Notifications
Pending: the owner chose to test first. Run a worker manually that stops on an owner decision. Two outcomes:
- If the Claude app pushes for a session waiting on input, use that.
- If not, choose between a desktop relay (a GitHub issue labelled `needs-owner`, picked up by a desktop task that sends a push notification) and GitHub's own notifications.

### Other limits
- Runs start in auto mode and stop on ask-rule matches.
- Cron expressions are UTC; no more often than hourly.
- 100 runs per hour per account.

## Checklist for the owner
1. Create `locksmith-dev`: Limited network, package managers on, paste `scripts/cloud-setup.sh` as the setup script.
2. Create `locksmith-research`: as above, plus the documentation domains.
3. Make sure the Claude GitHub App is installed on `locksmith-hq/locksmith`.
4. Branch protection: **owner decision 2026-11-16: not protected for now.** Revisit before the repo goes public or anyone else gets write access.
5. Start one interactive cloud session on `locksmith-dev` and confirm `just ci` passes, plus `just up` once F0 exists.

## GitHub Actions budget
GitHub Free gives a private repo $12 of Actions compute a month. Per-minute prices: Linux x64 $0.006, Windows $0.010, macOS $0.062. Source: https://docs.github.com/en/billing/concepts/product-billing/github-actions

How we stay inside it:
- **`ci.yml` (every PR):**
  - Linux only, with timeouts on every job.
  - A new push cancels the CI run it supersedes.
  - Path filters skip work that isn't needed, and Markdown-only PRs skip CI entirely. OpenSpec files still run.
  - Cheap checks (tree layout, task-edit guard, gitleaks) share one job.
  - Only `main` writes the Rust cache.
- **`ci-platforms.yml`:** macOS and Windows checks run only manually or on release tags.
- **`adversarial.yml`:** weekly instead of nightly.
- **Agents:**
  - Verify in the cloud VM first, because that compute is free.
  - Push at most once per run.
  - Never re-run or dispatch workflows.
  - The weekly review reports Actions usage.

## Scheduler design (why it looks like this)
The design follows Anthropic's long-running agent harness (https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents):
- One task per run.
- State lives in git and the `agent-log` issue, not in model memory.
- Each run starts by checking CI and running a baseline `just ci`.
- A task is ticked only after its verification command passes.
- An attempt cap stops runaway runs, and a task stuck across three runs becomes a `needs-owner` issue.
- `scripts/check-task-edits.sh` allows agents only to tick tasks, never to rewrite them, because the article found models edit Markdown task lists.
- CI is the independent verifier the agent cannot fake.

## Schedules (cloud routines, Israel time)

All four avoid peak hours (weekdays about 15:00–21:00).

| Routine | Model | Environment | When | Job |
|---|---|---|---|---|
| [Worker](https://claude.ai/code/routines/trig_01GtbNHhQ34w5h6Z6nj3xD4G) | Sonnet 5.5 (subagents on Haiku, Sonnet or Opus by task tier) | `locksmith-dev` | daily 07:05, 13:05, 22:05 | one OpenSpec task per run on `claude/change-<id>`, draft PR |
| [Weekly review](https://claude.ai/code/routines/trig_01NUtSWtRzUGw2AMQUpQrQZT) | Sonnet 5.5 + Opus reviewer | `locksmith-research` | Sat 10:35 (after the Saturday 10:00 weekly reset) | re-verify finished work, quality review, write the next change |
| [Daily health check](https://claude.ai/code/routines/trig_012bR8F2aWP91W3D9xGDpVUn) | Haiku 5.5 | Default | daily 08:30 | detects silent failures: worker silent for more than 24h, red CI on main, owner decisions waiting more than 3 days, finished PRs waiting more than 2 days; stays silent when healthy |
| [Rescue (Opus)](https://claude.ai/code/routines/trig_01QEJR9b7UBh6XeiCeAa7cv1) | Opus 5.5 | `locksmith-dev` | daily 09:35, 23:35 (exits at once if idle) | fixes the oldest `needs-rescue` issue at its root cause and checks the fix with an independent Opus evaluator; after 2 failed attempts it hands the issue to the owner |
| [Monthly research refresh](https://claude.ai/code/routines/trig_016jEjKwShdcdfhWKBcp8kHs) | Sonnet 5.5 | `locksmith-research` | 1st of month, 10:35 | re-checks OSS versions and licences, `cargo audit` and `npm audit`, new MCP servers, Infisical changes; draft PR only if something changed |

Only the `Claude_Code_Remote` connector is attached. The others were removed on purpose: least privilege.

## Escalation ladder

1. **Worker attempt 1.** The task runs on its tagged tier, then the worker runs the verification command and `just ci`.
2. **Independent evaluator.** A separate subagent (Sonnet, or Opus for `[opus]` tasks) checks the diff against the task, the spec and the security rules, and answers PASS or FAIL. This follows the evaluator-optimizer pattern.
3. **Worker attempt 2,** one tier up (Haiku, then Sonnet, then Opus), given the evaluator's reasons.
4. **`needs-rescue` issue.** The Opus rescue routine reproduces the failure, finds the root cause, fixes it and has the fix evaluated.
5. **`needs-owner` and a push notification.** This happens only after 2 failed Opus attempts, or when the task itself is wrong. The daily health check reports rescue issues that sit unhandled for more than 24 hours.

## How the owner is alerted
Agents act as the owner's GitHub account, and GitHub never notifies anyone about their own activity. So:
- **Claude app push:** the agent calls `PushNotification`. Whether that reaches the phone from a cloud run is still being tested on the first run.
- **Email:** `.github/workflows/owner-alert.yml` runs when an issue gets the `needs-owner` label. `github-actions[bot]` then @mentions `vars.OWNER_LOGIN` (currently `tomer555`), and GitHub sends an email and a GitHub mobile notification. This needs "@mentions → Email" turned on in GitHub settings → Notifications (it is on by default).
