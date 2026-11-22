<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="packages/ui/brand/app-icon-dark.svg">
  <img src="packages/ui/brand/app-icon-light.svg" alt="Locksmith logo" width="120" height="120">
</picture>

# Locksmith

**The open-source secrets platform built by an AI team, for AI agents.**

A full secrets platform for teams (vault, console, CLI, desktop app and gateway) whose core is agent access:<br>
coding agents use your credentials for Git, HTTP APIs, databases and AWS without ever holding them.

[![ci](https://github.com/locksmith-hq/locksmith/actions/workflows/ci.yml/badge.svg)](https://github.com/locksmith-hq/locksmith/actions/workflows/ci.yml)
[![adversarial](https://github.com/locksmith-hq/locksmith/actions/workflows/adversarial.yml/badge.svg)](https://github.com/locksmith-hq/locksmith/actions/workflows/adversarial.yml)
[![License: AGPL-3.0 / Apache-2.0](https://img.shields.io/badge/license-AGPL--3.0%20%2F%20Apache--2.0-blue)](#licences)
[![Rust](https://img.shields.io/badge/built%20with-Rust-orange?logo=rust)](rust-toolchain.toml)
![Status: pre-release](https://img.shields.io/badge/status-pre--release-yellow)

[The story](#the-story) · [What Locksmith is](#what-locksmith-is) · [How it works](#how-it-works) · [Built by AI](#built-by-ai-used-by-ai) · [Roadmap](#where-it-is-today) · [Quick start](#quick-start) · [Security](#security-promise)

</div>

---

## The story

AI agents are becoming the people who write, ship and operate software. They push code, call APIs, migrate databases and change cloud infrastructure, and every one of those actions needs a credential. Today that usually means a token pasted into `.env`, where it leaks into the agent's context, shell history, transcripts and logs, and stays valid until someone notices.

Secrets managers were built for humans and servers, not for an autonomous process that reads everything it can reach and can be talked into printing it. Locksmith is a secrets platform rebuilt around that new user:

- **Delegation, not handover.** The agent asks Locksmith to act; Locksmith signs, relays or injects the credential for a session a human started. The key never enters the agent's process.
- **Zero-knowledge by design.** The control plane stores only ciphertext. Values are sealed in your browser or on your machine and decrypted only inside a gateway, never by the server that stores them.
- **Every use is accountable.** Each session is scoped, short-lived and revocable in seconds, and every use lands in a tamper-evident, hash-chained audit ledger.

And Locksmith is itself built the way it expects software to be built from now on: by a team of AI agents, in the open, with a human owner setting direction. The same agents that write Locksmith are the users it protects.

## What Locksmith is

| | |
|---|---|
| 🔐 **Secrets vault** | Orgs, projects and environments; versioned secrets under envelope encryption (a per-version key wrapped to a gateway key in a KMS). Local vault on your machine, Hub for teams. |
| 🚪 **Agent gateway** | Relays for HTTP APIs, Git, Postgres and AWS (SigV4 and short-lived STS credentials). Host allowlists, response redaction, no secret on the agent host. |
| 🤖 **Agent connectors** | `smith` CLI, a local MCP server and hooks for Claude Code, Cursor and Codex; more agents (Gemini CLI, Copilot, Windsurf, Cline) and a remote Agent MCP on the way. |
| 🧑‍💼 **Human control** | A web console and a desktop app (Tauri, macOS and Linux) to see what every agent did, approve access, revoke one session or pause every agent at once. Secret values never render in the UI. |
| 📜 **Audit and detection** | Append-only, hash-chained audit ledger per org with verification and export; honey-token secrets that alert on any use. |
| 👥 **Team product** | Sign-in with email, Google or GitHub (any OIDC issuer when self-hosting), org members and roles, Cedar policies, time-boxed access requests, notifications to Slack and email. |
| 🏠 **Run it anywhere** | Our cloud, or self-host (one-command Compose and Helm installs are planned). Open source under AGPL-3.0 and Apache-2.0. |

## How it works

```mermaid
flowchart LR
    A["AI agent<br/>(Claude Code, Cursor, Codex)"] -- "lsk_ token / MCP / smith run" --> GW["Locksmith gateway<br/>(locksmithd locally)"]
    CP[("Control plane<br/>ciphertext only")] -- "wrapped keys" --> GW
    KMS["KMS<br/>(OpenBao locally)"] -. "unwrap" .-> GW
    GW -- "signs / relays / injects" --> G["Git"]
    GW --> H["HTTP APIs"]
    GW --> DB["Postgres"]
    GW --> AWS["AWS"]
    GW -. "every use" .-> L["Audit ledger"]
    U["You: console, desktop app, smith"] -- "sign in, approve, revoke" --> CP
```

1. You store a secret. It is encrypted before it leaves your browser or machine; the control plane only ever sees ciphertext.
2. You start a session for an agent (or approve its request) with a scope, a TTL and the hosts it may reach.
3. The agent gets an opaque `lsk_` token, a relay or an MCP tool, never the value.
4. The gateway unwraps the key, performs the call, redacts the response and writes an audit record.
5. You watch, revoke or pause from the console, the desktop app or `smith revoke`.

## Built by AI, used by AI

Locksmith is developed by a team of AI agents, each with its own GitHub App identity, working through issues and pull requests in this repository. A human owner sets direction and makes the calls the agents escalate. This team is the Avengers.

<table>
  <tr>
    <td align="center" width="25%"><img src="docs/agents/avatars/iron-man.png" width="120" alt="Iron Man"><br><b>Iron Man</b><br>Lead (Opus)<br><sub>Owns code quality and architecture, reviews merged work, rescues stuck tasks</sub></td>
    <td align="center" width="25%"><img src="docs/agents/avatars/nick-fury.png" width="120" alt="Nick Fury"><br><b>Nick Fury</b><br>PM (Opus)<br><sub>Owns the end goal, roadmap order, priorities and the board</sub></td>
    <td align="center" width="25%"><img src="docs/agents/avatars/hulk.png" width="120" alt="Hulk"><br><b>Hulk</b><br>Research (Opus)<br><sub>Smashes hard questions with primary sources</sub></td>
    <td align="center" width="25%"><img src="docs/agents/avatars/doctor-strange.png" width="120" alt="Doctor Strange"><br><b>Doctor Strange</b><br>Optimizer (local)<br><sub>Bends the team's schedules and prompts toward more shipped work</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="docs/agents/avatars/captain-america.png" width="120" alt="Captain America"><br><b>Captain America</b><br>Worker A (Sonnet)</td>
    <td align="center"><img src="docs/agents/avatars/spider-man.png" width="120" alt="Spider-Man"><br><b>Spider-Man</b><br>Worker B (Sonnet)</td>
    <td align="center"><img src="docs/agents/avatars/thor.png" width="120" alt="Thor"><br><b>Thor</b><br>Worker C (Sonnet)</td>
    <td><sub>Workers implement <a href="openspec/">OpenSpec</a> tasks around the clock, each on its own change and PR, checked by an independent evaluator.</sub></td>
  </tr>
</table>

<sub>Persona artwork depicts Marvel characters for fun. Locksmith is not affiliated with or endorsed by Marvel or Disney.</sub>

How the team works:

- **Spec-driven.** Every change is an [OpenSpec](openspec/) proposal with a design, specs and tasks, and every design cites its evidence in [`docs/research/`](docs/research/).
- **Harness first.** A local stack (`just up`) with Postgres, OpenBao, Keycloak and Grafana, exposed to agents through MCP, plus `just leak-scan`, which hunts every encoding of a canary secret through the DB, logs, traces and transcripts.
- **Adversarial by default.** Scripted and live-agent extraction attempts run on every PR and nightly.
- **Autonomous merge, with gates.** Every PR passes CI, the adversarial suite and an independent Claude merge review before it merges itself.

The playbooks the agents follow are in [`docs/agents/`](docs/agents/); how they run in the cloud is in [`docs/cloud-dev.md`](docs/cloud-dev.md).

## Where it is today

| Phase | Status |
|---|---|
| **0. Harness**: local stack, leak scanning, data and cloud foundations | ✅ Done |
| **1. First slice**: control plane, envelope crypto, HTTP gateway, agent connector, audit ledger, adversarial gate, desktop and web builds | ✅ Done |
| **2. Team product**: sign-in, cloud dev environment, web console, browser-sealed secrets, sessions and revoke, orgs, Cedar policies, access requests, notifications, remote MCP, honey tokens | 🚧 In progress |
| **3. Delegation beyond HTTP**: Git ✅, AWS STS, Postgres relay, workload identity for CI and Kubernetes | 🚧 In progress |
| **4. Deployable**: more agent plugins, one-command self-host, signed releases, SDKs | Planned |
| **5–6. Parity and GA**: rotation and dynamic secrets, syncs, Terraform and Kubernetes, SAML and SCIM, external pentest, Windows | Planned |

Full roadmap: [docs/roadmap.md](docs/roadmap.md).

## Security promise

- Agents never receive secret values. They get relay access, delegation or short-lived scoped credentials (`lsk_` tokens).
- Every protection is labelled honestly:
  - 🛡️ **Prevention**: the secret never reaches the agent (relays, signing, injection).
  - 📦 **Containment**: a leaked token is scoped, short-lived and revocable.
  - 🔎 **Detection**: redaction, honey tokens and the tamper-evident audit ledger show what happened.
- Unlock and export are never blocked because of licensing, billing or update failures.
- Everything that touches a secret is written in Rust; secrets live only in `secrecy`/`zeroize` types and are never printed, logged or serialised.

> [!WARNING]
> Locksmith is pre-release software. Do not rely on it to protect production credentials yet. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Quick start

You need Rust (see `rust-toolchain.toml`), Node 22, [just](https://github.com/casey/just) and Docker. macOS and Linux are supported today.

```sh
git clone https://github.com/locksmith-hq/locksmith
cd locksmith
just up     # start the local stack
just ci     # fmt, lint, tests, layout and task checks
just down   # stop the stack
```

### Use it with your agent

| Agent | Integration |
|---|---|
| Claude Code | Plugin with hooks, MCP server and skills: `/plugin marketplace add locksmith-hq/locksmith`, then `/plugin install locksmith@locksmith` |
| Cursor | Hooks and MCP config in [`integrations/cursor`](integrations/cursor) |
| Codex | Config in [`integrations/codex`](integrations/codex) |

What an agent may do without your passphrase is set in a human-owned `agent-policy.toml`: see [integrations/README.md](integrations/README.md).

## Repository layout

| Path | Contents |
|---|---|
| `crates/` | Rust libraries and binaries (`locksmithd`, `smith`, `locksmith-mcp`, crypto, gateway, audit) |
| `ee/` | source-available enterprise layer (Rust), see [LICENSING.md](LICENSING.md) |
| `services/` | axum backends (control plane, gateway) |
| `apps/` | web console, docs, desktop (Tauri), `api` (NestJS) |
| `packages/` | shared TypeScript and the design system |
| `integrations/` | thin agent plugins |
| `infra/` | Docker Compose stack (Helm and OpenTofu to come) |
| `tests/` | end-to-end and adversarial tests |
| `openspec/` | specs and changes |
| `scripts/` | tooling |

Product notes: [PRODUCT.md](PRODUCT.md).

## Licences

- Server components (`services/`, `apps/web`) are licensed under AGPL-3.0-only: see [LICENSE](LICENSE).
- SDKs, CLI, crates, plugins, schemas, desktop and docs are licensed under Apache-2.0: see [LICENSE-APACHE](LICENSE-APACHE).
- Vendored third-party data is listed in [THIRD_PARTY.md](THIRD_PARTY.md).

## Contributing

If Locksmith is useful to you, a ⭐ helps other people find it. Humans and agents are both welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
