# Proposal: M10c Secret groups

## Why

Related secrets belong together: Langfuse needs `LANGFUSE_PUBLIC_KEY` and `LANGFUSE_SECRET_KEY`
every time. Today `smith run` injects the binding's flat `keys` list, so an agent that needs
Langfuse gets every listed key or a hand-picked list.

## What Changes

- `.locksmith.toml` gains `[groups.<name>]` with `keys = [...]` (vault key names only, never values).
- `smith run --group <name>` (repeatable) injects exactly that group's keys. The daemon expands the
  group from the binding pinned at session start, so a group the agent adds to the file later is
  ignored (same rule as http hosts).
- `locksmith_list_keys`, `smith ls` and the desktop Keys screen show each key's groups.
- `smith group ls` shows the groups and their keys, and warns about keys missing from the vault.

## Usable outcome

`smith run --group langfuse -- npm test` injects the two Langfuse keys and nothing else.

## Out of scope (follow-up)

Enforcing groups in the agent policy (an allow-list of groups per project) and session scopes per
group. Creating groups from the desktop app.

## Impact

`ls-redact` binding, `ls-ipc` RunSpec, `locksmithd` run path, `smith-cli`, `locksmith-mcp`, desktop Keys.
