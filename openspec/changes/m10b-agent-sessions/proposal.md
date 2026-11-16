# Proposal: M10b Agent-started sessions with auto-block

## Why

Today a human starts every session (`smith session start`) because starting one needs the vault
passphrase. The intended flow is that the agent starts sessions and asks for keys itself, and only
ever passes them along (opaque `lsk_` tokens, `smith run`, relays). The control is then policy plus
automatic blocking on suspicious activity, not a human tap per session.

## What Changes

- `locksmith_start_session` MCP tool: project, env, scopes, requested TTL. The daemon grants it only
  inside a human-set policy in the user config (allowed projects/envs, scope cap, max TTL). Anything
  outside policy falls back to a human approval prompt (M14 approval center, M9 Touch ID).
- A signal scorer in the daemon over audited events. Strong signals block at once: a redaction hit
  on a secret, a rogue-client attempt, a hook deny of a secret read. Weak signals add to a score and
  block over a threshold: bursts, first use of a host or key, production access, repeated declined
  requests.
- Block action: revoke the lease, kill the agent process tree (M8), put the project in a cooldown
  that refuses new agent sessions until the human clears it. Audited with the reason, tray notice.
- Desktop: blocked state with reason and a Clear button in the Audit viewer.

## Usable outcome

Claude starts its own session for a pre-approved project and works. If it tries to read a secret
or behaves abnormally, the session is revoked and the project is locked for agents until you clear it.

## Out of scope

Unattended unlock of a locked vault: the vault still needs the human (passphrase or Touch ID) once.

## Depends on

M10 (MCP server), M8 (process kill), M9 and M14 (approval prompt).
