# Design: P3 agent plugins

## Context

`agents.rs` already generates hooks and MCP config for Claude Code, Cursor and Codex, and `integrations_match_generated` fails on drift. `hook_cmd.rs` parses each agent's JSON and answers in its format; `init_cmd.rs` and `doctor_m4.rs` iterate `agents::ALL`. P3 adds four agents plus a generic guide by extending those same seams, not by new mechanisms.

Observed constraint: the hook formats and config paths of the four new agents are not in this repo. The format facts below are assumptions from prior knowledge until task 1.1 records them with source URLs; no later task starts before 1.1 and 1.2 pass.

## Decisions and evidence

| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | Extend `agents.rs` with `Agent` variants and generate every config from it | Hand-written plugin files per agent (drift, as with early Claude Code files) | Existing drift test `integrations_match_generated`; `integrations/README.md` |
| 2 | Hook per agent only where the agent offers a blocking pre-tool event; otherwise MCP plus instructions, labelled detection or none | Pretend a rules or instructions file prevents reads | `openspec/config.yaml` rule: label protections honestly. Format facts recorded in `docs/research/agent-plugin-formats.md` (task 1.1) |
| 3 | One directory per agent, named for `just test <name>`: `gemini-cli`, `copilot`, `windsurf`, `cline`, `generic-mcp` | One combined `integrations/other` | `just test` resolves `integrations/<name>` and requires a `docs/testing.md` row |
| 4 | Copilot is one integration covering VS Code agent mode and the CLI, sharing the MCP file where formats match | Two directories | Roadmap row P3 lists them together; split only if task 1.1 shows incompatible formats |
| 5 | Smoke tests are recorded fixtures (agent payloads captured from the agent's documented schema or a real run) replayed through `smith hook` and the MCP stdio handshake; a live variant runs only when the agent CLI is on `PATH` | Live-only (needs vendor accounts, flaky in CI) | Same approach as `just test cursor` (files plus adversarial coverage); CI has no agent keys |
| 6 | No TypeScript in plugins | npm wrapper packages per agent | `integrations/README.md`: thin, no security logic; registry publishing is out of scope |
| 7 | Task 2.1 is met by fixtures derived from each vendor's documented hook schema and source (Gemini CLI, Copilot, Cline), each with a `SOURCE.md` naming the source URL, version and check date; payloads recorded from a live agent replace them later, they do not block P3 | Split 2.1 into a follow-up change waiting on a session with the vendor CLIs (needs paid vendor accounts, and leaves the design's own option unused) | Decision 5 allows "captured from the agent's documented schema"; a wrong assumed argument key on a known shell, read or edit tool fails closed (`unreadable()` denies a known tool that does not parse; `*-missing-command` and `*-missing-path` fixtures). The fail-closed condition is bounded by the paragraph below the table; a wrong assumed tool name still passes as unknown; Windsurf has no handler until recorded (P3-1). Lead, rescue #594 |

Bounded fail-closed rule for the doc-derived adapters (row 7, decision P3-2, lead rescue #594): two structural rules in `ls_hooks::adapters::handle` replace per-key patches. (1) Unrecognised shape denies: a registered tool event (Gemini `BeforeTool`, Copilot `preToolUse`/`PreToolUse`, Cline `PreToolUse`) whose tool name and input object are not found under the expected naming, or that carries two namings at once, is denied, never passed as an unknown tool; Copilot reads `toolName`/`toolArgs` or `tool_name`/`tool_input` under either event casing. (2) Every string is checked: for a known tool, besides its parsed primary argument, every string in the tool input (any depth, arrays included) except the tool's named content keys (command, file content, search pattern) is judged against the protected-path policy, so a secret path under a decoy or misnamed key denies. Fixtures: `*-shape-mismatch-*` and `*-decoy-key-*`. Remaining exposure is a wrong guessed tool name, which passes as unknown until recordings exist.

## OSS used

| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| none new (reuses `serde_json`, `toml` already in `smith-cli`) | MIT/Apache-2.0 | workspace | n/a | Config merge is a few lines on existing deps | None involved; plugins are Apache-2.0 |

Searched first: existing merge helpers in `agents.rs` (reused). If task 1.1 finds a maintained cross-agent config library that fits, record it here and prefer it; otherwise in-house stays, as the formats are small.

## Risks

- Vendor hook formats are young and change: the recorded fixtures carry the source URL and capture date, and `smith doctor` reports unsupported agent versions as unknown rather than protected.
- Windsurf and Cline may place user-level config outside the repo; `smith init` only writes repo-level files and prints the user-level step instead of editing home-directory files.
- A hook that cannot read the agent's payload must deny, not allow (fail closed).

## How an agent debugs this

- `smith doctor` shows per-agent state (detected, installed, hook available, protection label).
- `smith hook <agent> <event> < fixture.json` replays a payload; denials appear in the audit ledger (`smith audit` or `just audit-verify`).
- `UPDATE_INTEGRATIONS=1 cargo test -p smith-cli --bin smith agents` regenerates files; a plain run shows drift.
- `just test <name>` runs one integration; `just leak-scan` checks fixtures and files for canaries.
- MCP servers in `.mcp.json` give database, log and trace access via `just up`; nothing here adds a table or trace.
