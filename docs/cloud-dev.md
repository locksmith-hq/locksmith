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
- **Environment variables:** `BASH_MAX_TIMEOUT_MS=600000`, `CARGO_TERM_COLOR=never`. **No secrets here,** with one exception the owner accepted on 2026-11-18: the agent GitHub App keys (see "Agent identities"). Environment variables are readable by the model and by any command it runs.
- **Setup script:** a short bootstrap (pasted 2026-11-16) that finds the cloned repo and runs [`scripts/cloud-setup.sh`](../scripts/cloud-setup.sh), falling back to a built-in copy if the repo isn't present yet. Changes merged to that file apply without re-pasting. It installs build dependencies, `just`, the pinned toolchain, a prebuilt `cargo-nextest`, `gitleaks` and `cargo-deny` (`scripts/ci-tools.sh`) and `openspec`. It no longer pre-pulls compose images (that blew the 5-minute cache budget and hung the lead run on 2026-11-17); `just up` pulls them on demand.
- **Starting the stack:** each session starts it with `just up`, which the F0 docs tell the agent to run. A SessionStart hook in `.claude/settings.json` starts dockerd in the background (remote only; it does not pull images), so `just up` finds the daemon ready. **[test]** Whether Docker in the VM runs the full stack (lgtm needs about 1 to 2 GB RAM).

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

### 3. Later: `locksmith-aws-dev`, from P1 (phase 2)
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

## GitHub Actions
The repo is public, so standard runners are free. `ci`, `ci-platforms` and `adversarial` run on every PR and on `main` (see `AGENTS.md`, "CI policy").

## Scheduler design (why it looks like this)
The design follows Anthropic's long-running agent harness (https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents):
- Small steps per run; since 2026-11-17 several workers run at once, each on a different change (`scripts/change-status.sh`, per-change locks in `scripts/run-lock.sh`). Each change has a tracking issue kept current by the `change-sync` workflow.
- State lives in git and the `agent-log` issue, not in model memory.
- Each run starts by checking CI; nobody runs `just ci` locally (`just quick` instead).
- A task is ticked only after its verification command passes.
- An attempt cap stops runaway runs, and a stuck task becomes a `needs-rescue` issue for the lead; only the lead raises `needs-owner`.
- `scripts/check-task-edits.sh` allows agents only to tick tasks, never to rewrite them, because the article found models edit Markdown task lists.
- CI is the independent verifier the agent cannot fake.

## Schedules (cloud routines, Israel time)

Except the workers (their own PR events, plus each worker every 2 hours, 24/7), routines avoid peak hours (weekdays about 15:00–21:00).

| Routine | Model | Environment | When | Job |
|---|---|---|---|---|
| [Worker A (Captain America)](https://claude.ai/code/routines/trig_01GtbNHhQ34w5h6Z6nj3xD4G) | Sonnet 5.5 (subagents on Haiku, Sonnet or Opus by task tier) | `locksmith-dev` | every 2 hours: :05 UTC at even hours (owner 2026-11-22) | claims one ready change at a time (per-change lock on its tracking issue), parks blocked ones and takes the next; non-draft PR per change. Several workers may run at once |
| [Worker B (Spider-Man)](https://claude.ai/code/routines/trig_0157sQMWva4JP97dc6DqkPEM) | Sonnet 5.5 (same prompt as Worker A) | `locksmith-dev` | every 2 hours: :35 UTC at odd hours (owner 2026-11-22) | same as Worker A, as `spider-man`; with C, six worker starts every 3 hours |
| [Worker C (Thor)](https://claude.ai/code/routines/trig_013QMkh2C8t7h3z2AL3YvAXH) | Sonnet 5.5 (same prompt as Worker A) | `locksmith-dev` | every 2 hours: :50 UTC at even hours (owner 2026-11-22) | same as Worker A, as `thor`; a third worker between A and B |
| [Daily summary](https://claude.ai/code/routines/trig_01E29QPqddtqyaTR1FUjLKxT) | Haiku 5.5 | Default | daily 07:00 and 20:00 | updates the one daily-summary Artifact and sends a push; read-only, REST API only (GraphQL is blocked in cloud sessions) |
| [PM (Nick Fury)](https://claude.ai/code/routines/trig_01Dja9jHSJRqbcepRAGz9GUQ) | Opus 5.5 | its own environment | daily 08:00, plus `wake-agents.yml`: an owner `@locksmith-pm` tag at once; debate turns, `needs-work` and agent tags batched by the `tick` job every 2 h (secret `PM_FIRE_TOKEN`) | product: end goal, roadmap order, priorities and the board; hands technical findings to the lead as `for-lead` issues |
| [Lead (Iron Man)](https://claude.ai/code/routines/trig_01QEJR9b7UBh6XeiCeAa7cv1) | Sonnet 5.5 (Opus subagents for hard rescues; owner 2026-11-22) | `locksmith-research` | daily 09:35, plus `wake-agents.yml`: an owner `@locksmith-lead` tag at once; everything else (rescues, owner replies on its issues, debate turns, its failed PRs, main red over 2 h) batched by the `tick` job every 2 h (secret `LEAD_FIRE_TOKEN`) | tech lead (`docs/agents/lead.md`, replaced Rescue and the Learning loop 2026-11-17): rescues the oldest `needs-rescue` issue; reviews code merged since its last run for duplication, reinvented wheels, readability drift and over-specific solutions, and turns findings into fixes, unticked tasks or a `refactor-*` change |
| [Research (Hulk)](https://claude.ai/code/routines/trig_018kWxT3hop7LXdXkBN4HwNB) | Opus 5.5 | `locksmith-ada`: its own environment with Full network (not Default: the daily summary runs there and would see the research key) | no schedule; API only: `wake-agents.yml` fires it at once for an owner `@locksmith-ada`/`@locksmith-research` tag; agent tags and `needs-research` issues are batched by the `tick` job every 2 h (secret `RESEARCH_FIRE_TOKEN`; put its trigger id in `routing.json`) | answers one question per wake-up with sourced findings as a comment (`docs/agents/research.md`); never pushes code. Its own App (`locksmith-research`: issues write, contents read) limits what an injected web page can do |

GitHub triggers (web UI only; one per routine): the API stores filters as `filter.clauses[]` of `{field, operator, values}` with fields like `pr.author`, `pr.labels`, `pr.base_branch`, `pr.draft` and operators like `FILTER_OP_IN`, but `RemoteTrigger` cannot list or delete triggers. Not available as triggers: issue comments, CI results. The review stays in GitHub Actions because gate 6 trusts only the Claude bot identity; agents act as `tomer555` and could forge a routine's verdict.

Only the `Claude_Code_Remote` connector is attached. The others were removed on purpose: least privilege.

## Agent identities (GitHub Apps)
Agents are the Avengers: Iron Man (Lead), Nick Fury (PM), Captain America, Spider-Man and Thor (Workers A, B, C), Hulk (Research) and Doctor Strange (Optimizer, local, no App). `routing.json` accepts both the new and the old bot logins until every App is renamed; persona keys (`alfie`, `josie`, `AGENT_APP_KEY_*`, environment names) keep their old spelling because the cloud routine prompts use them.

**Each worker owns its PRs (owner 2026-11-20).** There is no separate event worker. `wake-agents.yml` fires the worker whose App opened a PR when that PR's merge review (`claude-review`) finishes or its CI fails, and the worker that opened a `needs-rescue` issue when it closes. Red main, a closed `needs-owner` issue and PRs opened by the owner go to Worker A. An owner tag `@locksmith-alfie`, `-josie` or `-harriet` wakes that worker (`@locksmith-worker`: Worker A). Each worker's API trigger token is a repo secret (`WORKER_A_FIRE_TOKEN`, `_B_`, `_C_`). Each role has a private GitHub App owned by `locksmith-hq`, installed only on this repo, with webhooks off. Avatars are in `docs/agents/avatars/`.

| Routine | App (new slug) | Access |
|---|---|---|
| Lead | `iron-man` (was `locksmith-linus`) | code, PRs, issues, workflows (write) |
| Worker A | `captain-america` (was `locksmith-alfie`) | code, PRs, issues (write) |
| Worker B | `spider-man` (was `locksmith-josie`) | code, PRs, issues (write) |
| Worker C | `thor` (was `locksmith-harriet`) | code, PRs, issues (write) |
| PM | `nick-fury` (was `locksmith-walt`) | PRs, issues (write); code (read) |

**Key per environment (owner, 2026-11-20).** The 2026-11-18 pause had one cause: a network secret is a fixed header, but the token request needs a JWT signed with the App's private key, and GitHub caps that JWT at 10 minutes. Like Renovate's self-hosted setup, each run now signs a fresh JWT from the App key and swaps it for a one-hour installation token. An environment with no App key at all still runs as the owner (`agent-start.sh` warns) until every key is set; one that holds other keys but not this persona's fails with `FAIL identity`.

How a run takes its app identity: one cloud environment per role, each holding only that role's App key (owner 2026-11-20): `locksmith-dev` for Workers A, B and C (keys `AGENT_APP_KEY_ALFIE`, `_JOSIE`, `_HARRIET`; no `AGENT_PERSONA`: each worker prompt passes its persona to `agent-start.sh`, owner 2026-11-20), `locksmith-lead` for the lead (`linus`), `locksmith-walt` for the PM (`walt`), and `locksmith-ada` (Full network, key `AGENT_APP_KEY_ADA`, `AGENT_PERSONA=ada`) for Research. A run can read every key in its environment, so different roles never share one (the workers are one role): otherwise a worker could post as the lead and the login-based routing in `route.sh` would mean nothing. The lead and PM environments set `AGENT_PERSONA=<persona>` and `AGENT_APP_KEY_<PERSONA>`. A run in an environment with App keys but none for its persona fails (`FAIL identity`) instead of acting as the owner. `scripts/agent-start.sh` calls `scripts/agent-identity.sh setup` at the start of every run. That script mints a one-hour installation token (signed with `AGENT_APP_KEY_<PERSONA>`, or locally the Keychain key), sets the git author, points pushes at github.com with that token, and puts a `gh` shim on PATH. If no token comes back or it is not accepted, it prints `FAIL identity` and exits 1, and the run stops without doing work: it never falls back to the owner account.

Owner setup:
1. In each routine's environment, set `AGENT_APP_KEY_<PERSONA>` to the base64 of that App's private key (`base64 -i key.pem`), only that routine's key, and delete the old network secret on `api.github.com/app/installations/`. A new App without a row in `agent-identity.sh` also sets `AGENT_APP_IDS="<app_id> <installation_id> <bot_user_id>"`.
2. Run each routine in its own environment.
3. Add the `locksmith-*[bot]` logins to the author filter of the lead's GitHub trigger, next to `tomer555`.

**Identity test (before any real routine switches).** A test App and environment prove the identity without touching the schedules:
1. Create the App `locksmith-test` (Contents, Issues, Pull requests: write; Metadata: read; webhooks off) and install it on this repo only.
2. Create the cloud environment `locksmith-identity-test` (copy of `locksmith-dev`) with `AGENT_PERSONA=test`, `AGENT_APP_KEY_TEST` and `AGENT_APP_IDS="<app_id> <installation_id> <bot_user_id>"` (bot user id: `gh api users/locksmith-test%5Bbot%5D -q .id`).
3. Create a routine "Identity test" in it with no schedule and the prompt `Run bash scripts/identity-smoke.sh and report its output.` Run it by hand.
It sets up the identity, pushes an empty commit, opens a PR, comments, labels and closes it, checking each is authored by `locksmith-test[bot]`. When it passes, set the real keys one routine at a time; delete the test App's key afterwards.

On the owner's Mac, the **optimizer** (`docs/agents/optimizer.md`, desktop scheduled task, 07:00 and 20:00, replaced the local lead 2026-11-19) runs as the owner in its own worktree `~/locksmith-optimizer`, detached at `origin/main`. It is the only agent that reads routine run logs (`RemoteTrigger`); it audits the schedules, agent communication and run efficiency, logs each cause on the pinned `harness-backlog` issue, and on Saturday at 07:00 builds the one weekly agent-system release (`claude/harness-release-<YYYY-WW>`), which the owner merges. It may only edit routine prompts; other routine changes go to the owner as `needs-owner`.

**Agent System v3 (#470, 2026-11-19).** Agent-system files (`docs/agents`, `.claude/skills`, agent scripts, workflows) change only in that weekly release or on a `*hotfix-*` branch (red main, a security fix, every run failing), for owner sessions too; `scripts/check-task-edits.sh` enforces it and `.github/CODEOWNERS` makes those PRs wait for the owner's approval. An owner `needs-owner` issue parks a change only when its next task is a `Gate:` task, so gates block just their own tasks. Each change has one tracking issue; per-task issues are retired.

Cloud runs never see the app keys; they see the one-hour installation token, which reaches only this repo with the access above. Revoke a key in the app's settings page.

## Escalation ladder

1. **Worker attempt 1.** The task runs on its tagged tier, then the worker runs the verification command and `just quick`.
2. **Independent evaluator.** A separate subagent (Sonnet, or Opus for `[opus]` tasks) checks the diff against the task, the spec and the security rules, and answers PASS or FAIL. This follows the evaluator-optimizer pattern.
3. **Worker attempt 2,** one tier up (Haiku, then Sonnet, then Opus), given the evaluator's reasons.
4. **`needs-rescue` issue,** the only way a worker asks for help: `Rescue:` when stuck, `Decision:` for an owner matter. the lead picks it up within 2 h (`tick`); it fixes or decides in git and closes the issue, which wakes a worker to continue the parked change.
5. **`needs-owner` and a push notification,** raised only by the lead: when its own two Opus attempts fail (same run), for an owner matter, or for a PM–lead debate that ended without agreement. The optimizer (`docs/agents/optimizer.md`) reports rescue latency; the daily health check routine no longer exists (2026-11-19).

## Routing and debates
`docs/agents/routing.json` says who may ask whom: roles (GitHub App logins, routine trigger, fire-token secret) and channels (issue labels: who opens, who is woken on open, on owner reply, on close). `scripts/route.sh` reads it for `wake-agents.yml` and enforces debates. Both are owner-only (task-edit guard).

**Owner tags.** An owner comment containing `@locksmith-lead`, `@locksmith-pm`, `@locksmith-worker` or `@locksmith-ada` (alias `@locksmith-research`), on any issue or PR, wakes exactly those roles. A comment by Ada (`locksmith-ada[bot]`) that tags roles wakes them too: that is how her answers reach the PM, lead and workers (`mentions` in `routing.json`). GitHub sends Apps nothing for a mention, so this is a text match, like `@claude`. Without a tag, an owner reply on `needs-owner` wakes the role named by the issue's `<!-- raised-by: x -->` marker (else the lead). Owner setup: create free orgs with those four names, so no stranger can register one and get notified by every tag.

The PM owns what and when; the lead owns how. A disagreement becomes a `debate` issue (`debate` skill). Turns alternate, each side gets at most `turns` (3), and roles come from GitHub App logins, so no agent can speak for the other side or skip the cap (while identities are paused, from a `<!-- role: x -->` marker instead). Agreement is recorded in git by the lead; agree-to-disagree or the cap turns the issue into a `needs-owner` decision with both positions side by side. At most 2×turns+1 wake-ups per debate.

To extend: add a role (logins, trigger, secret) or a channel to `routing.json`, pass the new secret in `wake-agents.yml`, add the label to its prefilter, and extend `route.sh selftest`.

## How the owner is alerted
Agents act as the owner's GitHub account, and GitHub never notifies anyone about their own activity. So:
- **Claude app push:** the agent calls `PushNotification`. Whether that reaches the phone from a cloud run is still being tested on the first run.
- **Email:** `.github/workflows/owner-alert.yml` runs when an issue gets the `needs-owner` label. The lead's App writes the @mention in the issue it opens; only for an issue a human account opened does `github-actions[bot]` edit the body to start with an @mention of `vars.OWNER_LOGIN` (currently `tomer555`), and GitHub sends an email and a GitHub mobile notification. This needs "@mentions → Email" turned on in GitHub settings → Notifications (it is on by default).

## Agent instructions and run metadata
The instructions for each routine live in `docs/agents/` (`common.md` plus one file per role). Each routine prompt only says to read those files from origin/main and follow them, so instruction changes are PRs the owner reviews. `scripts/check-task-edits.sh` fails any `claude/*` branch that touches them.

Every agent-log comment and every agent-opened issue ends with a `run-metadata` YAML block covering:
- timing, session id, SHAs and diff size, collected by `scripts/run-meta.sh`;
- outcome, attempts and evaluator verdict;
- each subagent's tier, duration, tokens and tool uses.

The weekly review turns these blocks into a stats table.

## Skills and scripts instead of long instructions
Agent guidance lives in repo skills (`.claude/skills/`), so each run loads only the procedure it is using. Rules are enforced by scripts:
- `agent-start.sh` and `agent-preflight.sh` check the environment at the start of each run;
- `bg.sh` runs long commands in the background;
- `run-meta.sh` builds the run's metadata block;
- `check-task-edits.sh` and `check-agent-docs.sh` are the guards.

`scripts/check-agent-docs.sh` caps the instruction size in CI:
- `common.md`: 660 words
- each role file: 400 words
- each skill: 500 words
- active lessons: 5

The lead routine must not increase the total. Its PRs merge through the same required checks as everything else, with no waiting window (owner decision, 2026-11-16).

## Independent review in GitHub Actions
`.github/workflows/claude-review.yml` runs `anthropics/claude-code-action@v1` with the `merge-review` skill whenever auto-merge is enabled on a PR and on every push to such a PR. It authenticates with the owner's Claude subscription through the `CLAUDE_CODE_OAUTH_TOKEN` repository secret, which the owner creates with `claude setup-token` and stores with `gh secret set`. It sets the required `merge-ready` status from its `merge-review <sha>: PASS|FAIL` verdict. Each review costs one Linux runner for up to 10 minutes and uses the Max subscription, not API credits.
