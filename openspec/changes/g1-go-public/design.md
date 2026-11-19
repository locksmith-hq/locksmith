# Design: G1 go public

## Context
Evidence gathered on 2026-11-18 from the repo: no `LICENSE` file; `Cargo.toml` workspace `license = "UNLICENSED"`; 296 commits scanned by `gitleaks detect` in 1.4 s gave 17 findings; `.gitleaksignore` already holds fingerprints for fake fixtures; `SECURITY.md` has two lines; the README still mentions M0–M16. Owner handle `tomer555` appears in CODEOWNERS and agent docs (public GitHub handle, fine); `PRODUCT.md`, `scripts/install.sh` and `docs/cloud-dev.md` mention it too and must be reviewed.

## Decisions and evidence
| Decision | Alternatives rejected | Evidence |
|---|---|---|
| Triage the existing history, do not rewrite it | `git filter-repo` before publishing | Findings are fixtures (`.gitleaksignore` comments, `aws_relay.rs`, SigV4 suite); rewrite breaks merge SHAs and is hard to reverse, so only a real secret justifies it and then needs a `needs-owner` decision (common.md). |
| AGPL-3.0 server, Apache-2.0 SDK/CLI/plugins/schemas | single licence | Fixed in `openspec/config.yaml` context; this change only makes files and manifests agree. |
| One `public-check.sh` in `just ci`, not a workflow | new GitHub Actions job | CI policy allows seconds-long hygiene, and workflow edits are protected. |
| Denylist of patterns plus a path allowlist for agent docs | delete `docs/agents` and `.claude` | The agent harness is part of the open-source story; only secrets and private identifiers must not leak. Owner decides if they should be hidden (open question below). |
| Keep `ci` disabled until the owner flips visibility | agents enable it | Settings changes are owner-only (common.md, #307). |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| `gitleaks` | MIT | already in preflight | check at apply | history and tree secret scan | tool only |
| `cargo-deny` | MIT/Apache-2.0 | already used | check at apply | licence allow/deny list | tool only |
| `lychee` (candidate) | MIT/Apache-2.0 | pin at apply | record at apply | link check, if lighter than a 20-line shell check | tool only; skipped if it needs a network in CI |

Built in-house: the small denylist and licence-manifest check, because nothing off the shelf knows our private-identifier list. Searched first: gitleaks custom rules (used for the denylist if they fit) and `reuse` (REUSE compliance, rejected as heavier than needed).

## Risks and open questions
- A real secret in history: stop, open `needs-owner` with the fingerprint (never the value), recommend rotation first and rewrite only if the owner agrees.
- Whether `.claude/`, `docs/agents/` and agent personas stay public is an owner call; default is public with a denylist.
- Vendored `aws-model.json` and SigV4 fixtures carry third-party licences: record them in `THIRD_PARTY.md`.

## How an agent debugs this
`gitleaks detect --redact -v`, `bash scripts/public-check.sh`, `cargo deny check licenses`, `git log -S<pattern> --oneline` to locate when a finding entered, `just ci`. No MCP servers are involved; nothing here reads the stack.
