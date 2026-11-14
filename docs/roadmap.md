# Locksmith Roadmap (v6)

Each milestone is one OpenSpec change in `openspec/changes/<id>/`. Run it with `/opsx:apply <id>`.
When it ships and its gate passes, archive it with `/opsx:archive <id>` so its delta specs merge into
`openspec/specs/`.

Estimates assume one senior Rust engineer plus a coding agent. Shaded milestones can run in parallel
once their dependencies land.

| # | Change id | You can use it to… | Gate (blocking) | Est. | Depends on |
|---|---|---|---|---|---|
| M0 | `m0-foundation` | install `smith`, run `smith doctor`, and `smith self update` from internal releases | CI green on mac+linux, release dry run, doctor JSON schema test | 1w | n/a |
| M1 | `m1-local-vault` | keep secrets in an encrypted local vault (`smith add/get-meta/ls/rm`), back it up with a recovery phrase | crypto KATs, tamper tests, recovery round-trip | 1.5w | M0 |
| M2 | `m2-run-and-redact` | delete `.env`: `smith run -- npm test` injects secrets and masks every echo | redactor property tests (all encodings, chunk splits) | 1.5w | M1 |
| M3 | `m3-daemon-sessions` | unlock once per session, `smith status`, `smith revoke`, tamper-evident audit | adversarial gate A4a (rogue same-UID client rejected) | 2w | M2 |
| M4 | `m4-agent-guardrails` | `smith init` a repo: Claude Code / Cursor / Codex hooks block `.env` dumps and secret pastes, pre-commit scanner | gate A6 (agent cannot read or commit secrets) | 1w | M3 |
| M5 | `m5-git-delegation` | the agent pushes to private GitHub/GitLab with no token in its reach | **gate A1 (Git adversarial)** | 1w | M3 |
| M6 | `m6-http-db-relays` | call Stripe/OpenAI/etc. with `lsk_` opaque tokens, run Postgres/MySQL migrations through a password-less relay | **gate A3 (DB relay)**, A3b (HTTP) | 2w | M3 |
| M7 | `m7-aws-delegation` | the agent uses the AWS CLI/SDKs with no AWS keys in its reach | **gate A2 (AWS adversarial)** | 1.5w | M6 |
| M8 | `m8-process-containment` | builds and postinstall scripts cannot reach the broker, and revoke kills the whole agent tree | **gates A4 + A5** | 2w | M5, M6 |
| M9 | `m9-hardware-unlock-and-rotation` | Touch ID unlock, vault key rotation, external audit anchors | rotation crash-injection test, biometric re-enroll test | 2w | M3 |
| M10 | `m10-mcp-server` | the agent lists keys and asks a human to create or rotate secrets through MCP | gate A7 (zero bytes to the LLM) | 1w | M3 |
| M11 | `m11-diagnostics-support` | `smith doctor --fix`, `smith diag bundle`, opt-in telemetry and crash reports | bundle secret-free proof test | 1w | M3 |
| M12 | `m12-update-delivery` | signed auto-updates with channels, staged rollout, kill switch, rollback | TUF attack suite (rollback, freeze, mix-and-match) | 2w | M0, M11 |
| M13 | `m13-subscription-licensing` | buy Pro/Team via Stripe, activate offline-verifiable licenses, gate features | never-hostage test suite | 2w | M12 |
| M14 | `m14-desktop-app` | manage projects, secrets, sessions and audit in a Tauri app with tray approvals | Playwright/WebDriver e2e | 2.5w | M9, M13 |
| M15 | `m15-team-vaults` | share end-to-end encrypted vaults with a team, central policy and audit | sync server blind-storage test | 3w | M13 |
| M16 | `m16-ga-hardening` | GA: Windows parity, notarized and signed installers, external pentest | pentest criticals = 0, full adversarial suite | 3w | all |

Critical path to a private beta (M0→M5, plus M11/M12 basic): about 8 weeks.
Critical path to paid launch (adds M13, M14): about 16 weeks.

## Adversarial suite (`tests/adversarial`)

These come from the v5 Phase 0 gates. Every case runs two ways: as a **scripted attack** (a
deterministic shell script, runs in CI) and as a **live-agent run** (Claude Code headless with
`claude -p` and an attack prompt, run nightly). A live run fails if any vault secret, or any encoding
of one, shows up in the agent transcript, the repo, or the shell history.

| Id | Attack | Milestone |
|---|---|---|
| A1 | Extract the Git token (`git credential fill`, read gitconfig, run the helper directly, sniff the proxy) | M5 |
| A2 | Extract AWS keys (`export-credentials`, env, `~/.aws/cli/cache`, proxy sniffing) | M7 |
| A3 | Extract the DB password (env, config, `ss`/`lsof`, relay banner) | M6 |
| A3b | Extract an API key through response reflection or header echo | M6 |
| A4 | A hostile postinstall script reaches the broker or steals a capability | M3 (rogue client), M8 (in-tree) |
| A5 | Revoke under load: nothing succeeds after revoke returns | M8 |
| A6 | `cat .env`, `printenv`, stage `.claude/settings.local.json`, paste a secret in chat | M4 |
| A7 | The MCP surface leaks a value | M10 |
| A8 | The diagnostics bundle or logs contain a secret | M11 |
| A9 | Update attacks: downgrade, freeze, malicious mirror | M12 |

## Parallel tracks (same monorepo)

| Id | Change id | Delivers | Starts after |
|---|---|---|---|
| W1 | `w1-landing-site` | `apps/web`: landing, security, waitlist, pricing (from `features.toml`), legal | M0 |
| W2 | `w2-docs-site` | `apps/docs`: Starlight docs, generated CLI/schema/doctor refs, `llms.txt` | M0 |
| P1 | `p1-agent-plugins` | `integrations/*`: Claude Code, Cursor, Codex, Grok Build, OpenHands, Gemini CLI, VS Code, GitHub Action, devcontainer | M4 (wave 1), M10 (wave 2) |
