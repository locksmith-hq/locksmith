# Proposal: M10e Relay-only keys and a policy-owned relay boundary

## Why

Live testing of M10/m10b showed that `smith run` hands the real value to a child process the agent
writes, and output redaction only catches the exact value and a few encodings. With the `TEST`
canary, reversed, spaced, split, ROT13, character-code and case-changed output all got through.
Redaction is an accident guard, not a boundary.

A review of Infisical's Agent Vault (open source, MITM credential proxy) and of the 2026 market
shows one pattern that holds: the agent never holds the real value, and a proxy attaches it to
requests to destinations the human approved. Two gaps stop Locksmith's relays from being that
boundary for agent-started sessions today:

1. The relay host list comes from `.locksmith.toml` (`[http].keys.*.hosts`), passed by the MCP
   server at `AgentSessionStart` and pinned. An agent can write its own host into the file before it
   starts a session, and the relay then attaches the real key to requests to that host.
2. Nothing stops an agent from asking for the same key through `smith run`.

## What Changes

- **Relay-only keys.** The human-owned agent policy lists which keys an agent session may *inject*
  (`run`). Every other key is relay-only for agent sessions: `smith run` / `--only` / `--all` refuse it
  with a clear message, and it is reachable only through the http relay, git, aws and db delegation.
  Default for a project with no `inject` list: nothing injectable.
- **Policy-owned relay boundary.** For agent-started sessions the allowed upstream hosts per key come
  from the policy (`[projects.<p>.http.<KEY>] hosts = [...]`), intersected with the binding. A host
  the policy does not list is refused (audited `BLOCKED relay_host`), whatever the binding says.
- **Network guard in the relay.** Refuse upstream connections to loopback, private, link-local, CGN and
  cloud-metadata addresses, checked on the resolved IP right before connecting (DNS rebinding safe),
  with an explicit allowlist in the policy for intentional internal targets (local Langfuse, etc).
- **Response redaction proof.** A test and a doc line establishing that the relay redacts the key in
  response headers and bodies (an echo endpoint such as `/headers` must not return it).
- **Canary tests.** The `TEST` key, never injected, plus an extraction suite that must find nothing
  through any agent-reachable path.

## Usable outcome

An agent session can call the Langfuse API through an `lsk_` token. It cannot run
`smith run --only LANGFUSE_…`, cannot point the relay at a host the human did not list, and the
Sessions tab shows which keys that session may inject.

## Out of scope (follow-ups)

Agent proposals with human approval (request a new key or host), forced routing / sandbox
(HTTPS_PROXY container with a firewall), placeholder substitution in path/query/body, strict deny for
unmatched hosts outside relay keys, rate limits, honeytoken auto-block (M10b 2.x), team roles.

## Impact

`locksmithd` policy + run + relay authorization, `ls-proxy` (guard, host check), `smith-cli` messages,
`locksmith-mcp` status, desktop Sessions detail, skills text, docs.
