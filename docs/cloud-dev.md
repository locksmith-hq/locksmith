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
- **Environment variables:** `BASH_MAX_TIMEOUT_MS=600000`, `CARGO_TERM_COLOR=never`. **No secrets here,** with one exception the owner accepted on 2026-11-18: the agent GitHub App keys (see "Agent identities" in `locksmith-roadmap` `ops/cloud-dev.md`). Environment variables are readable by the model and by any command it runs.
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

## Schedules, agents and routing
The scheduler design, the cloud routines and their schedules, agent identities (GitHub Apps), the escalation
ladder, routing, owner alerts, run metadata and the agent skills and scripts moved out of this repo:
- `locksmith-hq/locksmith-roadmap`: [`ops/cloud-dev.md`](https://github.com/locksmith-hq/locksmith-roadmap/blob/main/ops/cloud-dev.md) (schedules, identities, routing; private) and `crew.json`.
- `locksmith-hq/claude-ai-crew`: the role prompts, skills, scripts and workflows.

The merge gate stays here: `.github/workflows/claude-review.yml` with `scripts/review-tier.sh` and `.claude/skills/merge-review`.
