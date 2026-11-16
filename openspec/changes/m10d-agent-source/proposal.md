# Proposal: M10d Session source and self-reported model

## Why

The desktop Sessions tab and `smith status` show a session as an id, a pid and a command. With
agent-started sessions (M10b) the human cannot tell at a glance which tool holds a lease: Claude
Code in a terminal, Claude Code inside the desktop app, Cursor, Codex. The model in use is also
useful context, but only the agent knows it.

## What Changes

- The daemon derives a `source` (kind plus label) and an optional `host` (terminal, multiplexer or
  IDE) for every lease from executable paths the kernel reports for the lease root and a few of its
  ancestors. Arguments and environment are never read. Unknown binaries show as `other` with their
  name; unreadable ones as `unknown`.
- `locksmith_start_session` and `Request::AgentSessionStart` take optional `agent` and `model`
  strings (64 printable ASCII characters at most). They are stored and audited as self-reported and
  never used for authorization.
- `LeaseInfo` (IPC and `@locksmith/api-types`) gains `root_exe`, `started_by`, `source`, `host`
  and `report`. `smith status` prints them; `--json` includes them.
- The `locksmith-sessions` plugin skill tells the agent to pass its client name and model id.

## Usable outcome

`smith status` and the desktop show "Claude desktop app, model claude-fable-5-2 (self-reported)"
or "Claude Code in iTerm2" for each session, and "other: node" when Locksmith does not know.

## Out of scope

Desktop UI (a follow-up builds the Sessions tab on these types). Verifying the model.
