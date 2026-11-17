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
  - ghcr.io is on the documented allowlist, but **it returned 403 in practice** (first worker run, 2026-11-16). Use Docker Hub images instead, for example `openbao/openbao:2.7.2`.
  - github.com, including release assets, and Ubuntu apt
- **Extra allowed domains:** none for now.
- **Environment variables:** `BASH_MAX_TIMEOUT_MS=600000`, `CARGO_TERM_COLOR=never`. **No secrets here.** Environment variables are readable by the model and by any command it runs.
- **Setup script:** a short bootstrap (pasted 2026-11-16) that finds the cloned repo and runs [`scripts/cloud-setup.sh`](../scripts/cloud-setup.sh), falling back to a built-in copy if the repo isn't present yet. Changes merged to that file apply without re-pasting. It installs build dependencies, `just`, the pinned toolchain, a prebuilt `cargo-nextest`, `gitleaks` and `cargo-deny` (`scripts/ci-tools.sh`) and `openspec`. It no longer pre-pulls compose images (that blew the 5-minute cache budget and hung the lead run on 2026-11-17); `just up` pulls them on demand.
- **Starting the stack:** each session starts it with `just up`, which the F0 docs tell the agent to run. A SessionStart hook can automate this once F0 lands. **[test]** Whether Docker in the VM runs the full stack (lgtm needs about 1 to 2 GB RAM).

### 2. `locksmith-research`: used by the weekly review and planning runs
- **Network:** Limited, with package managers, plus these documentation hosts:
  - `docs.aws.amazon.com`, `aws.amazon.com`
  - `www.postgresql.org`
  - `docs.rs`
  - `*.github.io`
  - `code.claude.com`, `docs.claude.com`
  - `nexte.st`, `insta.rs`, `www.cedarpolicy.com`, `openbao.org`, `grafana.com`
  - `reddit.com`, `www.reddit.com`, `old.reddit.com`, `medium.com`, `*.medium.com` (added 2026-11-17): user-written pages, so they are hints only. Act on a claim only after confirming it on the registry, the project's repo or its official docs, and cite that source.
- **Why separate:** the worker never needs open web access, so a prompt-injected web page can't reach a session that runs code with a wider network. **[test]** Whether WebSearch and WebFetch obey the environment allowlist. If they do, add domains here as research needs them; never switch to Full.

### 3. Later: `locksmith-aws-dev`, from phase 4 (P1)
- **Baseline infrastructure and guardrails** (IAM, SCPs, budget) deploy from **GitHub Actions using OIDC**. Claude writes OpenTofu and opens a PR. `tofu plan` runs with a read-only role, and `tofu apply` runs on merge with a scoped deploy role.
- The reason: AWS requests are signed with SigV4, so they can't use the cloud "network secrets" proxy, and putting AWS keys in environment variables would expose them to the model. That breaks the very rule this product exists to enforce.
- **The AWS MCP Server** (managed, by AWS) runs on the owner's laptop through Remote Control with IAM Identity Center short-lived credentials, so no key enters the cloud VM. After D2 (AWS STS), Claude sessions get it through Locksmith itself. This is dogfooding.
  - **Reads** (logs, describe calls, cost) run freely.
  - **Writes need the owner's approval, one change at a time.** Before each one, Claude posts a change brief: what changes, monthly cost and the effect on the $5 budget, blast radius, security effect, and how to roll back. A `PreToolUse` hook forces the approval prompt for every mutating AWS call, whatever the permission mode.
  - Resources created this way are tagged `created-by=claude-mcp` and imported into OpenTofu or destroyed before the session ends.
  - The MCP role can never change IAM, Organizations, SCPs, Budgets or Identity Center. Those change only through OpenTofu PRs.
- **Budget: $5/month for the dev account.** About $1–2 idle: an always-on base stack with Aurora paused at 0 ACU, plus an on-demand session stack (`just aws-up` / `just aws-down`) that auto-destroys. A budget action in the management account attaches a deny-create SCP at $5. Standing SCPs block other regions, ALB, NAT gateways, interface endpoints and large instances. Details: A0 design decisions 16–18.

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
  - workers: event-driven (review verdicts, merges, owner replies, red main) plus Worker A every 4 hours as the safety net, about 6 scheduled runs a day; Worker B disabled (owner 2026-11-17)
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
- Small steps per run; since 2026-11-17 several workers run at once, each on a different change (`scripts/change-status.sh`, per-change locks in `scripts/run-lock.sh`). Each change has a tracking issue kept current by the `change-sync` workflow.
- State lives in git and the `agent-log` issue, not in model memory.
- Each run starts by checking CI and running a baseline `just ci`.
- A task is ticked only after its verification command passes.
- An attempt cap stops runaway runs, and a task stuck across three runs becomes a `needs-owner` issue.
- `scripts/check-task-edits.sh` allows agents only to tick tasks, never to rewrite them, because the article found models edit Markdown task lists.
- CI is the independent verifier the agent cannot fake.

## Schedules (cloud routines, Israel time)

Except the workers (events, plus every 4 hours, 24/7), routines avoid peak hours (weekdays about 15:00–21:00).

| Routine | Model | Environment | When | Job |
|---|---|---|---|---|
| [Worker](https://claude.ai/code/routines/trig_01GtbNHhQ34w5h6Z6nj3xD4G) | Sonnet 5.5 (subagents on Haiku, Sonnet or Opus by task tier) | `locksmith-dev` | every 4 hours at :05, 24/7: safety net for missed events (owner 2026-11-17) | claims one ready change at a time (per-change lock on its tracking issue), parks blocked ones and takes the next; non-draft PR per change. Several workers may run at once |
| [Worker B](https://claude.ai/code/routines/trig_01FcnFP64Q1CJ8cFVEjprLAj) | Sonnet 5.5 (same prompt as Worker) | `locksmith-dev` | **disabled** (owner 2026-11-17: with about two changes ready it mostly found the lock taken) | a second concurrent worker; re-enable when the backlog grows |
| [Worker (events)](https://claude.ai/code/routines/trig_01JUGABHdyZuNMJSYdEKSfJx) | Sonnet 5.5 (worker prompt, checks out `origin/main` first) | `locksmith-dev` | GitHub: PR labeled, labels `review-passed`/`review-failed` (set by `claude-review.yml` from the verdict), author `tomer555`, base `main`, not draft. API: `wake-agents.yml` fires it when the owner replies on a `needs-owner` issue or main CI fails (secret `ROUTINE_FIRE_TOKEN`) | merges or fixes a PR the moment its review verdict lands, applies owner replies and fixes red main within minutes. Events only wake it: `worker-has-work.sh` decides, so dropped or duplicate events are harmless |
| [Worker (PR merged)](https://claude.ai/code/routines/trig_01EhiJrUX4Zbb6MBhgQ9uHBH) | Sonnet 5.5 (same prompt) | `locksmith-dev` | GitHub: PR closed and merged, author `tomer555`, base `main` (a routine takes one GitHub trigger, so this is its own routine) | starts the next change, archive or plan as soon as a PR lands |
| [Daily summary](https://claude.ai/code/routines/trig_01E29QPqddtqyaTR1FUjLKxT) | Haiku 5.5 | Default | daily 17:30 | updates the one daily-summary Artifact and sends a push; read-only, REST API only (GraphQL is blocked in cloud sessions) |
| [Weekly review](https://claude.ai/code/routines/trig_01NUtSWtRzUGw2AMQUpQrQZT) | Sonnet 5.5 + Opus reviewer | `locksmith-research` | Sat 10:35 (after the Saturday 10:00 weekly reset) | re-verify finished work, quality review, write the next change |
| [Daily health check](https://claude.ai/code/routines/trig_012bR8F2aWP91W3D9xGDpVUn) | Haiku 5.5 | Default | daily 08:30 | detects silent failures: worker silent for more than 24h, red CI on main, owner decisions waiting more than 3 days, finished PRs waiting more than 2 days; stays silent when healthy |
| [Lead (Opus)](https://claude.ai/code/routines/trig_01QEJR9b7UBh6XeiCeAa7cv1) | Opus 5.5 | `locksmith-research` | daily 09:35, 23:35 (passes with nothing to do are skipped), plus GitHub: issue opened with label `needs-rescue`, author `tomer555` | tech lead (`docs/agents/lead.md`, replaced Rescue and the Learning loop 2026-11-17): rescues the oldest `needs-rescue` issue; reviews run metadata for stuck, slow or wasteful runs and fixes the causes in scripts or skills; reviews code merged since its last run for duplication, reinvented wheels, readability drift and over-specific solutions, and turns findings into fixes, unticked tasks or a `refactor-*` change |
| [Monthly research refresh](https://claude.ai/code/routines/trig_016jEjKwShdcdfhWKBcp8kHs) | Sonnet 5.5 | `locksmith-research` | 1st of month, 10:35 | re-checks OSS versions and licences, `cargo audit` and `npm audit`, new MCP servers, Infisical changes; draft PR only if something changed |

GitHub triggers (web UI only; one per routine): the API stores filters as `filter.clauses[]` of `{field, operator, values}` with fields like `pr.author`, `pr.labels`, `pr.base_branch`, `pr.draft` and operators like `FILTER_OP_IN`, but `RemoteTrigger` cannot list or delete triggers. Not available as triggers: issue comments, CI results. The review stays in GitHub Actions because gate 6 trusts only the Claude bot identity; agents act as `tomer555` and could forge a routine's verdict.

Only the `Claude_Code_Remote` connector is attached. The others were removed on purpose: least privilege.

## Escalation ladder

1. **Worker attempt 1.** The task runs on its tagged tier, then the worker runs the verification command and `just ci`.
2. **Independent evaluator.** A separate subagent (Sonnet, or Opus for `[opus]` tasks) checks the diff against the task, the spec and the security rules, and answers PASS or FAIL. This follows the evaluator-optimizer pattern.
3. **Worker attempt 2,** one tier up (Haiku, then Sonnet, then Opus), given the evaluator's reasons.
4. **`needs-rescue` issue.** The Opus lead routine reproduces the failure, finds the root cause, fixes it and has the fix evaluated.
5. **`needs-owner` and a push notification.** This happens only after 2 failed Opus attempts, or when the task itself is wrong. The daily health check reports rescue issues that sit unhandled for more than 24 hours.

## How the owner is alerted
Agents act as the owner's GitHub account, and GitHub never notifies anyone about their own activity. So:
- **Claude app push:** the agent calls `PushNotification`. Whether that reaches the phone from a cloud run is still being tested on the first run.
- **Email:** `.github/workflows/owner-alert.yml` runs when an issue gets the `needs-owner` label. `github-actions[bot]` then @mentions `vars.OWNER_LOGIN` (currently `tomer555`), and GitHub sends an email and a GitHub mobile notification. This needs "@mentions → Email" turned on in GitHub settings → Notifications (it is on by default).

## Agent instructions and run metadata
The instructions for each routine live in `docs/agents/` (`common.md` plus one file per role). Each routine prompt only says to read those files from origin/main and follow them, so instruction changes are PRs the owner reviews. `scripts/check-task-edits.sh` fails any `claude/*` branch that touches them.

Every agent-log comment and every agent-opened issue ends with a `run-metadata` YAML block covering:
- timing, session id, SHAs and diff size, collected by `scripts/run-meta.sh`;
- outcome, attempts and evaluator verdict;
- each subagent's tier, duration, tokens and tool uses.

The weekly review turns these blocks into a stats table.

## Skills and scripts instead of long instructions
Agent guidance lives in repo skills (`.claude/skills/`), so each run loads only the procedure it is using. Rules are enforced by scripts:
- `merge-gate.sh` runs the merge gates;
- `agent-start.sh` and `agent-preflight.sh` check the environment at the start of each run;
- `bg.sh` runs long commands in the background;
- `run-meta.sh` builds the run's metadata block;
- `check-task-edits.sh` and `check-agent-docs.sh` are the guards.

`scripts/check-agent-docs.sh` caps the instruction size in CI:
- `common.md`: 600 words
- each role file: 400 words
- each skill: 500 words
- active lessons: 5

The lead routine must not increase the total. Its PRs merge through the same gates as everything else, with no waiting window (owner decision, 2026-11-16).

## Independent review in GitHub Actions
`.github/workflows/claude-review.yml` runs `anthropics/claude-code-action@v1` with the `merge-review` skill whenever the `ready-to-merge` label is added and on every push to a labelled PR. It authenticates with the owner's Claude subscription through the `CLAUDE_CODE_OAUTH_TOKEN` repository secret, which the owner creates with `claude setup-token` and stores with `gh secret set`. Gate 6 of `merge-gate.sh` requires its `merge-review <sha>: PASS` verdict for the head SHA. Each review costs one Linux runner for up to 10 minutes and uses the Max subscription, not API credits.
