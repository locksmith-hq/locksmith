# Proposal: M2 Run and Redact

## Why

After M1, secrets are safe at rest but nothing can use them. The fastest path to daily use is
v5 Mode C: inject secrets into one command, and run its output through the streaming redactor so
an agent reading the terminal never sees the values. This is the milestone where a developer can
delete `.env` for real.

## What Changes

- `smith run [--project P] [--env E] [--only KEY,...] -- <cmd...>` spawns the command with secrets in
  its environment. A PTY is used when stdout is a TTY, pipes otherwise. stdout and stderr go through
  the redactor.
- `ls-redact`: a streaming multi-encoding Aho-Corasick redactor (plain, base64 at 3 alignments plus
  url-safe, hex lower/upper, percent-encoded, JSON-escaped, `user:pass` Basic-auth form), chunk
  carry-over, UTF-8 safe boundaries, a 20 ms idle flush.
- A project binding file `.locksmith.toml` (committed, no secrets): project name, default
  environment, the key list each command needs.
- `smith env-template` writes `.env.example` with names only.
- Mode C is labelled lowest assurance (docs/v6-review.md §1.8), and `smith run --explain` prints
  what is and is not protected.
- Doctor checks: `redact.selftest`, `run.pty_available`.

## Usable outcome

`smith run -- npm test` and `claude` launched with `smith run -- claude` both work without a `.env`.
Any echo of a secret in their output appears as `[REDACTED:STRIPE_KEY]`.

## Capabilities

### New Capabilities
- `secret-execution`: Running commands with injected secrets and a project binding.
- `output-redaction`: Streaming detection and masking of secret values in output.

### Modified Capabilities

## Out of scope

- Unlock caching. Each `smith run` prompts until M3 adds the daemon.
- Protection from the child process itself reading its own environment. That is inherent to
  Mode C, and M5–M8 provide the delegated alternatives.

## Impact

New crate `ls-redact` and `smith-cli run`. Dependencies: `aho-corasick`, `portable-pty`, `base64`,
`hex`, `percent-encoding`.
