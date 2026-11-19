# Design: D1 Git delegation

## Context
- Shipped: the local daemon forwarder (`crates/ls-proxy/src/{forward,github}.rs`, `smith git setup|credential` in `crates/smith-cli/src/git_cmd.rs`) injects a PAT or App installation token for the single-user daemon. The hosted gateway (`services/gateway/src/relay.rs`) takes the JSON relay only and holds request and response bodies as `Bytes`.
- Reuse: credential parsing and installation-token minting from `ls-proxy::github`, binding and grant checks, egress allowlist (`egress.rs`), the redactor (`ls-redact`) and the audit sink already used by `/v1/relay`.
- Agents hold only an agent token (S4). Git is pointed at the gateway with `url.<gateway>/git/github.com/.insteadOf=https://github.com/` and a credential helper that returns the agent token, never the GitHub credential.

## Goals / Non-Goals
**Goals:** hosted `git clone/fetch/push` over HTTPS with no GitHub credential on the agent side; streamed bodies; per-binding repository and service limits; ledger events.
**Non-Goals:** SSH, other hosts, per-ref policy (T2), pack content inspection, cloud deployment.

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **Smart-HTTP reverse proxy route in the gateway** with streaming bodies (`axum::body::Body` into `reqwest` stream). | Buffer the body (OOM on big pushes); a git remote helper binary (new protocol code on the agent). | Git HTTP protocol docs (git-scm.com/docs/http-protocol); the existing M5 forwarder already proves the pattern locally. |
| 2 | **Agent authenticates with its agent token via a Git credential helper** (`smith git credential`), reusing M5 setup. | Embedding a token in the remote URL (lands in `.git/config`, `ps`, history). | `smith git` M5 design; AGENTS.md security rules. |
| 3 | **Allow only the three smart-HTTP paths**; map `git-upload-pack` to `fetch` and `git-receive-pack` to `push`. | Generic path passthrough (turns the route into an open relay for the GitHub API). | Git HTTP protocol path set. |
| 4 | **Redact headers and `text/plain` error bodies only**, not pack streams. | Scan packs (binary, huge, and the agent already owns that data). | Containment is labelled honestly; adversarial gate G2 style test on the error channel. |
| 5 | **Reuse `ls-proxy::github` credential parsing and App token minting** rather than rewriting. | Duplicating JWT minting in the gateway. | Already in-tree and tested. |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| reqwest (workspace) | MIT/Apache-2.0 | workspace (streaming feature) | n/a | streamed upstream request | not AGPL |
| axum (workspace) | MIT | workspace | n/a | route and streaming body | not AGPL |
| git (test fixture, `git http-backend`) | GPL-2.0, test-time tool only, not linked | system | n/a | local smart-HTTP fixture requiring the credential | not shipped |

**[verify]** crate versions and the reqwest `stream` feature at apply. Built in-house: only the route glue; a maintained Rust Git smart-HTTP proxy crate was searched for first and none fits a streaming, injected-credential gateway.

## How an agent debugs this
`just up` and `just api`; run the gateway (`just gateway`); fixture `git http-backend` behind a tiny server from `tests/`. Ledger: `GET /v1/audit/events` (`git.fetch`, `git.push`, denied), `just audit-verify`, `just leak-scan`; gateway spans in Tempo, logs in Loki via the Grafana MCP; `smith doctor` for the Git setup.

## Risks
Large pushes and timeouts (bound request and idle timeouts); gateway memory (a streaming test asserts the bound); credential in `Authorization` echoed by a hostile upstream (redaction of headers).

## Contract: `GitBinding` and the route (task 1.1)
The gateway has no OpenAPI document, so the contract is this section and `services/gateway/src/git.rs`.

Route: `GET /git/{host}/{owner}/{repo}[.git]/info/refs?service=git-upload-pack|git-receive-pack`, `POST /git/{host}/{owner}/{repo}[.git]/git-upload-pack` and `.../git-receive-pack`. Anything else is denied before any credential is read.

Bindings file (TOML, beside `[[binding]]`):
```toml
[[git_binding]]
secret_id = "0197c1f0-0000-7000-8000-000000000003"
host = "github.com"          # exact, lowercase, no scheme or port
repo_prefix = "acme/widgets" # "owner" (all its repos) or "owner/repo"
services = ["fetch"]         # fetch = git-upload-pack, push = git-receive-pack
# allow_private_hosts = true # local test fixture only
```
Ledger events: `git.fetch`, `git.push`, and a denial event; no credential or pack data. `GitBinding::authorize` is the pure check (path allow-list, host and repository, service) that runs first.
